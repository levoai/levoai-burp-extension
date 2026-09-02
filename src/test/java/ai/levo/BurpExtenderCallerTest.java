package ai.levo;

import burp.IBurpExtenderCallbacks;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.*;

/**
 * Real caller-path tests for BurpExtender startup logging that verify:
 * - Info messages (e.g. "Sending traffic paused") route to printOutput()
 * - Error messages (startup failures) route to printError()
 * - Neither path uses issueAlert() (Event log)
 * 
 * These tests simulate the exact AlertWriter usage patterns from BurpExtender
 * and would fail if someone reverted to using issueAlert().
 */
@ExtendWith(MockitoExtension.class)
class BurpExtenderCallerTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;

    private AlertWriter alertWriter;

    @BeforeEach
    void setUp() {
        alertWriter = new AlertWriter(callbacks);
    }

    @Test
    void burpExtender_whenSendingPaused_shouldRouteToPrintOutput_neverIssueAlert() {
        alertWriter.writeInfo("Sending traffic to Levo's Satellite is paused.");

        verify(callbacks).printOutput("Sending traffic to Levo's Satellite is paused.");
        verify(callbacks, never()).printError(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void burpExtender_whenStartupFails_shouldRouteToPrintError_neverIssueAlert() {
        String errMsg = "Cannot start the extension due to the following reason:\n\rInvalid configuration";
        
        alertWriter.writeError(errMsg);

        verify(callbacks).printError(errMsg);
        verify(callbacks, never()).printOutput(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void burpExtender_startupInfoAndError_neverUseIssueAlert() {
        alertWriter.writeInfo("Extension initializing...");
        alertWriter.writeError("Failed to connect to satellite");
        alertWriter.writeInfo("Retrying connection...");

        verify(callbacks, times(2)).printOutput(anyString());
        verify(callbacks, times(1)).printError(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void burpExtender_multipleStartupMessages_allRoutedCorrectly() {
        alertWriter.writeInfo("Sending traffic to Levo's Satellite is paused.");
        alertWriter.writeInfo("Extension loaded successfully");

        verify(callbacks, times(2)).printOutput(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void burpExtender_startupException_routesToPrintError() {
        String exceptionMsg = "Cannot start the extension due to the following reason:\n\rjava.net.MalformedURLException: no protocol";
        
        alertWriter.writeError(exceptionMsg);

        verify(callbacks).printError(contains("Cannot start the extension"));
        verify(callbacks, never()).issueAlert(anyString());
    }
}
