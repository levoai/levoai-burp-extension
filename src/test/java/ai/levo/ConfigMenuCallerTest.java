package ai.levo;

import burp.IBurpExtenderCallbacks;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.Method;

import static org.mockito.Mockito.*;

/**
 * Real caller-path tests for ConfigMenu that construct and exercise the actual
 * ConfigMenu class, forcing exception handlers to run and verifying they route
 * to printOutput() (Output tab) via writeInfo(), never issueAlert() or printError().
 * 
 * Per Buchi's constraint: ConfigMenu catch blocks must stay on Output, not Errors.
 * These tests would fail if someone reverted to issueAlert() or switched to printError().
 */
@ExtendWith(MockitoExtension.class)
class ConfigMenuCallerTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;

    @Mock
    private LevoSatelliteService levoSatelliteService;

    private AlertWriter alertWriter;
    private ConfigMenu configMenu;
    private MockedStatic<JOptionPane> jOptionPaneMock;

    @BeforeEach
    void setUp() {
        lenient().when(callbacks.loadExtensionSetting(anyString())).thenReturn("");
        alertWriter = new AlertWriter(callbacks);
        configMenu = new ConfigMenu(callbacks, alertWriter, levoSatelliteService);
        ConfigMenu.IS_SENDING_ENABLED = false;
        
        jOptionPaneMock = mockStatic(JOptionPane.class);
        jOptionPaneMock.when(() -> JOptionPane.showInputDialog(
                any(), anyString(), anyString(), anyInt(), any(), any(), any()))
                .thenReturn("http://test.example.com");
    }

    @AfterEach
    void tearDown() {
        if (jOptionPaneMock != null) {
            jOptionPaneMock.close();
        }
    }

    @Test
    void configMenu_satelliteUrlUpdateThrows_routesToPrintOutput_neverIssueAlertOrPrintError() throws Exception {
        doThrow(new RuntimeException("Connection failed"))
                .when(levoSatelliteService).updateSatelliteUrl(anyString());

        JMenuItem menuItem = invokePrivateMethod("getConfigureSatelliteUrlConfigMenuItem");
        triggerActionListener(menuItem);

        verify(callbacks).printOutput(contains("Cannot update Satellite URL:"));
        verify(callbacks).printOutput(contains("Connection failed"));
        verify(callbacks, never()).issueAlert(anyString());
        verify(callbacks, never()).printError(anyString());
    }

    @Test
    void configMenu_organizationIdUpdateThrows_routesToPrintOutput_neverIssueAlertOrPrintError() throws Exception {
        doThrow(new RuntimeException("Invalid org"))
                .when(levoSatelliteService).updateOrganizationId(anyString());

        JMenuItem menuItem = invokePrivateMethod("getConfigureOrganizationIdConfigMenuItem");
        triggerActionListener(menuItem);

        verify(callbacks).printOutput(contains("Cannot update Organization ID:"));
        verify(callbacks).printOutput(contains("Invalid org"));
        verify(callbacks, never()).issueAlert(anyString());
        verify(callbacks, never()).printError(anyString());
    }

    @Test
    void configMenu_environmentUpdateThrows_routesToPrintOutput_neverIssueAlertOrPrintError() throws Exception {
        doThrow(new RuntimeException("Bad environment"))
                .when(levoSatelliteService).updateEnvironment(anyString());

        JMenuItem menuItem = invokePrivateMethod("getConfigureEnvironmentConfigMenuItem");
        triggerActionListener(menuItem);

        verify(callbacks).printOutput(contains("Cannot update Environment:"));
        verify(callbacks).printOutput(contains("Bad environment"));
        verify(callbacks, never()).issueAlert(anyString());
        verify(callbacks, never()).printError(anyString());
    }

    private JMenuItem invokePrivateMethod(String methodName) throws Exception {
        Method method = ConfigMenu.class.getDeclaredMethod(methodName);
        method.setAccessible(true);
        return (JMenuItem) method.invoke(configMenu);
    }

    private void triggerActionListener(JMenuItem menuItem) {
        ActionListener[] listeners = menuItem.getActionListeners();
        if (listeners.length > 0) {
            listeners[0].actionPerformed(new ActionEvent(menuItem, ActionEvent.ACTION_PERFORMED, "test"));
        }
    }
}
