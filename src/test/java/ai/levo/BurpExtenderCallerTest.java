package ai.levo;

import burp.BurpExtender;
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

import static org.mockito.Mockito.*;

/**
 * Real caller-path tests for BurpExtender that construct and exercise the actual
 * BurpExtender class, verifying:
 * - Info messages (e.g. "Sending traffic paused") route to printOutput()
 * - Error messages (startup failures) route to printError()
 * - Neither path uses issueAlert() (Event log)
 * 
 * These tests would fail if someone reverted to using issueAlert().
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BurpExtenderCallerTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;

    private MockedStatic<ConfigMenu> configMenuMock;
    private MockedStatic<JOptionPane> jOptionPaneMock;
    private MockedStatic<SwingUtilities> swingMock;

    @BeforeEach
    void setUp() {
        configMenuMock = mockStatic(ConfigMenu.class);
        configMenuMock.when(ConfigMenu::getBurpFrame).thenReturn(null);
        
        jOptionPaneMock = mockStatic(JOptionPane.class);
        swingMock = mockStatic(SwingUtilities.class);
    }

    @AfterEach
    void tearDown() {
        if (configMenuMock != null) configMenuMock.close();
        if (jOptionPaneMock != null) jOptionPaneMock.close();
        if (swingMock != null) swingMock.close();
    }

    @Test
    void burpExtender_whenSendingPaused_routesToPrintOutput_neverIssueAlert() {
        when(callbacks.loadExtensionSetting(ConfigMenu.ENABLE_SENDING_CFG_KEY)).thenReturn("true");
        when(callbacks.loadExtensionSetting(ConfigMenu.LEVO_SATELLITE_URL_CFG_KEY)).thenReturn("https://satellite.levo.ai");
        when(callbacks.loadExtensionSetting(ConfigMenu.LEVO_ORGANIZATION_ID_CFG_KEY)).thenReturn("org123");
        when(callbacks.loadExtensionSetting(ConfigMenu.LEVO_ENVIRONMENT_CFG_KEY)).thenReturn("staging");

        BurpExtender extender = new BurpExtender();
        extender.registerExtenderCallbacks(callbacks);

        verify(callbacks).printOutput("Sending traffic to Levo's Satellite is paused.");
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void burpExtender_whenStartupFails_routesToPrintError_neverIssueAlert() {
        when(callbacks.loadExtensionSetting(anyString())).thenReturn("");
        doThrow(new RuntimeException("Startup failure"))
                .when(callbacks).setExtensionName(anyString());

        BurpExtender extender = new BurpExtender();
        extender.registerExtenderCallbacks(callbacks);

        verify(callbacks).printError(contains("Cannot start the extension"));
        verify(callbacks).printError(contains("Startup failure"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void burpExtender_errorPath_neverUsesIssueAlert() {
        when(callbacks.loadExtensionSetting(anyString())).thenReturn("");
        doThrow(new RuntimeException("Config error")).when(callbacks).setExtensionName(anyString());

        BurpExtender extender = new BurpExtender();
        extender.registerExtenderCallbacks(callbacks);

        verify(callbacks, atLeastOnce()).printError(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }
}
