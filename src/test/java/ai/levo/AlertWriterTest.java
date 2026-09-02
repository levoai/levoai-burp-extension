package ai.levo;

import burp.IBurpExtenderCallbacks;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.*;

/**
 * Tests for AlertWriter to ensure info logs go to Output tab (printOutput)
 * and error logs go to Errors tab (printError), not to Event log (issueAlert).
 */
@ExtendWith(MockitoExtension.class)
class AlertWriterTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;

    private AlertWriter alertWriter;

    @BeforeEach
    void setUp() {
        alertWriter = new AlertWriter(callbacks);
    }

    @Test
    void writeInfo_shouldCallPrintOutput_notPrintErrorOrIssueAlert() {
        String message = "Test info message";

        alertWriter.writeInfo(message);

        verify(callbacks).printOutput(message);
        verify(callbacks, never()).printError(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void writeError_shouldCallPrintError_notPrintOutputOrIssueAlert() {
        String message = "Test error message";

        alertWriter.writeError(message);

        verify(callbacks).printError(message);
        verify(callbacks, never()).printOutput(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void writeInfo_withEmptyMessage_shouldStillCallPrintOutput() {
        alertWriter.writeInfo("");

        verify(callbacks).printOutput("");
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void writeError_withEmptyMessage_shouldStillCallPrintError() {
        alertWriter.writeError("");

        verify(callbacks).printError("");
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void multipleInfoMessages_shouldNeverUseIssueAlert() {
        alertWriter.writeInfo("Message 1");
        alertWriter.writeInfo("Message 2");
        alertWriter.writeInfo("Message 3");

        verify(callbacks, times(3)).printOutput(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void multipleErrorMessages_shouldNeverUseIssueAlert() {
        alertWriter.writeError("Error 1");
        alertWriter.writeError("Error 2");

        verify(callbacks, times(2)).printError(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void mixedInfoAndError_shouldRouteToCorrectCallbacks() {
        alertWriter.writeInfo("Info message");
        alertWriter.writeError("Error message");
        alertWriter.writeInfo("Another info");

        verify(callbacks, times(2)).printOutput(anyString());
        verify(callbacks, times(1)).printError(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }
}
