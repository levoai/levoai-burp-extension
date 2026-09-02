package ai.levo;

import burp.IBurpExtenderCallbacks;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.mockito.Mockito.*;

/**
 * Real caller-path tests for ConfigMenu that construct and exercise the actual
 * ConfigMenu class, covering:
 * - Exception handlers (lines 269, 307, 345)
 * - Enable/disable send toggle (lines 143, 159, 163)
 * - Scope toggle (lines 180, 186)
 * - Null-frame paths (lines 202, 219)
 * 
 * Per Buchi's constraint: All ConfigMenu logging routes to Output tab via writeInfo(),
 * never issueAlert() or printError(). Tests would fail if reverted to issueAlert().
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ConfigMenuCallerTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;

    @Mock
    private LevoSatelliteService levoSatelliteService;

    private AlertWriter alertWriter;
    private ConfigMenu configMenu;
    private MockedStatic<JOptionPane> jOptionPaneMock;
    private MockedStatic<ConfigMenu> configMenuStaticMock;

    @BeforeEach
    void setUp() {
        when(callbacks.loadExtensionSetting(anyString())).thenReturn("");
        alertWriter = new AlertWriter(callbacks);
        
        configMenuStaticMock = mockStatic(ConfigMenu.class, CALLS_REAL_METHODS);
        configMenuStaticMock.when(ConfigMenu::getBurpFrame).thenReturn(null);
        
        configMenu = new ConfigMenu(callbacks, alertWriter, levoSatelliteService);
        ConfigMenu.IS_SENDING_ENABLED = false;
        ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = false;
        
        jOptionPaneMock = mockStatic(JOptionPane.class);
        jOptionPaneMock.when(() -> JOptionPane.showInputDialog(
                any(), anyString(), anyString(), anyInt(), any(), any(), any()))
                .thenReturn("http://test.example.com");
    }

    @AfterEach
    void tearDown() {
        if (jOptionPaneMock != null) jOptionPaneMock.close();
        if (configMenuStaticMock != null) configMenuStaticMock.close();
    }

    @Test
    void configMenu_satelliteUrlUpdateThrows_routesToPrintOutput_neverIssueAlert() throws Exception {
        doThrow(new RuntimeException("Connection failed"))
                .when(levoSatelliteService).updateSatelliteUrl(anyString());

        JMenuItem menuItem = invokePrivateMethod("getConfigureSatelliteUrlConfigMenuItem");
        triggerActionListener(menuItem);

        verify(callbacks).printOutput(contains("Cannot update Satellite URL:"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_organizationIdUpdateThrows_routesToPrintOutput_neverIssueAlert() throws Exception {
        jOptionPaneMock.when(() -> JOptionPane.showInputDialog(
                any(), anyString(), anyString(), anyInt(), any(), any(), any()))
                .thenReturn("123e4567-e89b-12d3-a456-426614174000");
        doThrow(new RuntimeException("Invalid org"))
                .when(levoSatelliteService).updateOrganizationId(anyString());

        JMenuItem menuItem = invokePrivateMethod("getConfigureOrganizationIdConfigMenuItem");
        triggerActionListener(menuItem);

        verify(callbacks).printOutput(contains("Cannot update Organization ID:"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_invalidOrganizationId_isRejectedWithoutSaving() throws Exception {
        jOptionPaneMock.when(() -> JOptionPane.showInputDialog(
                any(), anyString(), anyString(), anyInt(), any(), any(), any()))
                .thenReturn("not-a-uuid");

        JMenuItem menuItem = invokePrivateMethod("getConfigureOrganizationIdConfigMenuItem");
        triggerActionListener(menuItem);

        verify(levoSatelliteService, never()).updateOrganizationId(anyString());
        verify(callbacks, never()).saveExtensionSetting(eq(ConfigMenu.LEVO_ORGANIZATION_ID_CFG_KEY), anyString());
        verify(callbacks).printOutput(contains("Cannot update Organization ID:"));
        verify(callbacks).printOutput(contains("must be a UUID"));
        verify(callbacks, never()).issueAlert(anyString());
        verify(callbacks, never()).printError(anyString());
    }

    @Test
    void configMenu_validOrganizationId_isTrimmedAndSaved() throws Exception {
        jOptionPaneMock.when(() -> JOptionPane.showInputDialog(
                any(), anyString(), anyString(), anyInt(), any(), any(), any()))
                .thenReturn("  123e4567-e89b-12d3-a456-426614174000  ");

        JMenuItem menuItem = invokePrivateMethod("getConfigureOrganizationIdConfigMenuItem");
        triggerActionListener(menuItem);

        verify(levoSatelliteService).updateOrganizationId("123e4567-e89b-12d3-a456-426614174000");
        verify(callbacks).saveExtensionSetting(
                ConfigMenu.LEVO_ORGANIZATION_ID_CFG_KEY, "123e4567-e89b-12d3-a456-426614174000");
        verify(callbacks, never()).issueAlert(anyString());
        verify(callbacks, never()).printError(anyString());
    }

    @Test
    void configMenu_environmentUpdateThrows_routesToPrintOutput_neverIssueAlert() throws Exception {
        doThrow(new RuntimeException("Bad environment"))
                .when(levoSatelliteService).updateEnvironment(anyString());

        JMenuItem menuItem = invokePrivateMethod("getConfigureEnvironmentConfigMenuItem");
        triggerActionListener(menuItem);

        verify(callbacks).printOutput(contains("Cannot update Environment:"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_enableSendingWithoutOrgId_routesToPrintOutput_neverIssueAlert() throws Exception {
        when(callbacks.loadExtensionSetting(ConfigMenu.LEVO_ORGANIZATION_ID_CFG_KEY)).thenReturn("");
        ConfigMenu.IS_SENDING_ENABLED = false;

        JCheckBoxMenuItem enableMenuItem = getEnableSendingMenuItem();
        enableMenuItem.setSelected(true);
        triggerActionListener(enableMenuItem);

        verify(callbacks).printOutput("Please set the Levo Organization Id first.");
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_enableSendingSuccess_routesToPrintOutput_neverIssueAlert() throws Exception {
        when(callbacks.loadExtensionSetting(ConfigMenu.LEVO_ORGANIZATION_ID_CFG_KEY))
                .thenReturn("123e4567-e89b-12d3-a456-426614174000");
        when(callbacks.loadExtensionSetting(ConfigMenu.LEVO_ENVIRONMENT_CFG_KEY)).thenReturn("staging");
        when(callbacks.loadExtensionSetting(ConfigMenu.LEVO_SATELLITE_URL_CFG_KEY)).thenReturn("https://satellite.levo.ai");
        ConfigMenu.IS_SENDING_ENABLED = false;

        JCheckBoxMenuItem enableMenuItem = getEnableSendingMenuItem();
        enableMenuItem.setSelected(true);
        triggerActionListener(enableMenuItem);

        verify(callbacks).printOutput(contains("Starting to send the traffic to Levo"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_disableSending_routesToPrintOutput_neverIssueAlert() throws Exception {
        ConfigMenu.IS_SENDING_ENABLED = true;

        JCheckBoxMenuItem enableMenuItem = getEnableSendingMenuItem();
        enableMenuItem.setSelected(false);
        triggerActionListener(enableMenuItem);

        verify(callbacks).printOutput("Stopped sending the traffic to Levo.");
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_enableScopeRestriction_routesToPrintOutput_neverIssueAlert() throws Exception {
        ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = false;

        JCheckBoxMenuItem scopeMenuItem = getScopeMenuItem();
        scopeMenuItem.setSelected(true);
        triggerActionListener(scopeMenuItem);

        verify(callbacks).printOutput(contains("only traffic from defined target scope"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_disableScopeRestriction_routesToPrintOutput_neverIssueAlert() throws Exception {
        ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = true;

        JCheckBoxMenuItem scopeMenuItem = getScopeMenuItem();
        scopeMenuItem.setSelected(false);
        triggerActionListener(scopeMenuItem);

        verify(callbacks).printOutput(contains("traffic from all targets"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_nullFrameOnRun_routesToPrintOutput_neverIssueAlert() throws Exception {
        reset(callbacks);
        when(callbacks.loadExtensionSetting(anyString())).thenReturn("");
        
        configMenu.run();

        verify(callbacks).printOutput(contains("Cannot add Levo's configuration menu"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_nullFrameOnUnload_routesToPrintOutput_neverIssueAlert() throws Exception {
        reset(callbacks);
        
        configMenu.extensionUnloaded();

        verify(callbacks).printOutput(contains("Cannot remove Levo's configuration menu"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    private JMenuItem invokePrivateMethod(String methodName) throws Exception {
        Method method = ConfigMenu.class.getDeclaredMethod(methodName);
        method.setAccessible(true);
        return (JMenuItem) method.invoke(configMenu);
    }

    private JCheckBoxMenuItem getEnableSendingMenuItem() throws Exception {
        Field cfgMenuField = ConfigMenu.class.getDeclaredField("cfgMenu");
        cfgMenuField.setAccessible(true);
        
        configMenu.run();
        
        JMenu cfgMenu = (JMenu) cfgMenuField.get(configMenu);
        for (int i = 0; i < cfgMenu.getItemCount(); i++) {
            JMenuItem item = cfgMenu.getItem(i);
            if (item instanceof JCheckBoxMenuItem && 
                item.getText() != null && 
                item.getText().contains("Send traffic")) {
                return (JCheckBoxMenuItem) item;
            }
        }
        throw new RuntimeException("Enable sending menu item not found");
    }

    private JCheckBoxMenuItem getScopeMenuItem() throws Exception {
        Field cfgMenuField = ConfigMenu.class.getDeclaredField("cfgMenu");
        cfgMenuField.setAccessible(true);
        
        if (cfgMenuField.get(configMenu) == null) {
            configMenu.run();
        }
        
        JMenu cfgMenu = (JMenu) cfgMenuField.get(configMenu);
        for (int i = 0; i < cfgMenu.getItemCount(); i++) {
            JMenuItem item = cfgMenu.getItem(i);
            if (item instanceof JCheckBoxMenuItem && 
                item.getText() != null && 
                item.getText().contains("target scope")) {
                return (JCheckBoxMenuItem) item;
            }
        }
        throw new RuntimeException("Scope menu item not found");
    }

    private void triggerActionListener(JMenuItem menuItem) {
        ActionListener[] listeners = menuItem.getActionListeners();
        if (listeners.length > 0) {
            listeners[0].actionPerformed(new ActionEvent(menuItem, ActionEvent.ACTION_PERFORMED, "test"));
        }
    }
}
