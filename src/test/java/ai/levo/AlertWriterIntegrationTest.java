package ai.levo;

import burp.IBurpExtenderCallbacks;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.*;

/**
 * Integration-level tests verifying that callers using AlertWriter
 * route info logs to printOutput and error logs to printError,
 * and never use issueAlert (Event log).
 * 
 * This simulates how HttpMessagePublisher, ConfigMenu, and other callers
 * use AlertWriter to log messages.
 */
@ExtendWith(MockitoExtension.class)
class AlertWriterIntegrationTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;

    private AlertWriter alertWriter;

    @BeforeEach
    void setUp() {
        alertWriter = new AlertWriter(callbacks);
    }

    @Test
    void callerLoggingSuccess_shouldRouteToPrintOutput_notIssueAlert() {
        String successMessage = "Sent the HTTP message for: example.com/api/test to Levo's Satellite.";
        
        alertWriter.writeInfo(successMessage);

        verify(callbacks).printOutput(successMessage);
        verify(callbacks, never()).printError(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void callerLoggingError_shouldRouteToPrintError_notIssueAlert() {
        String errorMessage = "Cannot send HTTP message to Levo. Status code(500): Connection refused";
        
        alertWriter.writeError(errorMessage);

        verify(callbacks).printError(errorMessage);
        verify(callbacks, never()).printOutput(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void callerLoggingConfigChange_shouldRouteToPrintOutput_notIssueAlert() {
        String configMessage = "Starting to send the traffic to Levo at address: https://satellite.levo.ai";
        
        alertWriter.writeInfo(configMessage);

        verify(callbacks).printOutput(configMessage);
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void callerLoggingConfigError_shouldRouteToPrintError_notIssueAlert() {
        String errorMessage = "Cannot update Satellite URL: Invalid URL format";
        
        alertWriter.writeError(errorMessage);

        verify(callbacks).printError(errorMessage);
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void callerLoggingTrafficPaused_shouldRouteToPrintOutput_notIssueAlert() {
        String pausedMessage = "Sending traffic to Levo's Satellite is paused.";
        
        alertWriter.writeInfo(pausedMessage);

        verify(callbacks).printOutput(pausedMessage);
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void callerLoggingStartupError_shouldRouteToPrintError_notIssueAlert() {
        String startupError = "Cannot start the extension due to the following reason:\r\nInvalid configuration";
        
        alertWriter.writeError(startupError);

        verify(callbacks).printError(startupError);
        verify(callbacks, never()).printOutput(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void typicalCallerWorkflow_infoAndErrorMessages_neverUseIssueAlert() {
        alertWriter.writeInfo("Extension loaded");
        alertWriter.writeInfo("Sent message to Levo");
        alertWriter.writeError("Failed to send message");
        alertWriter.writeInfo("Retrying...");
        alertWriter.writeInfo("Message sent successfully");

        verify(callbacks, times(4)).printOutput(anyString());
        verify(callbacks, times(1)).printError(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }
}
