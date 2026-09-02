package ai.levo;

import burp.IBurpExtenderCallbacks;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.concurrent.atomic.AtomicLong;

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

    @Test
    void writeInfoRateLimited_logsFirstOccurrenceImmediately() {
        AtomicLong now = new AtomicLong(1_000L);
        AlertWriter rateLimitedWriter = new AlertWriter(callbacks, now::get);

        rateLimitedWriter.writeInfoRateLimited("text/html", "Dropping because content-type 'text/html' is not instrumented");

        verify(callbacks, times(1)).printOutput(
                "Dropping because content-type 'text/html' is not instrumented");
    }

    @Test
    void writeInfoRateLimited_suppressesRepeatsWithinWindow() {
        AtomicLong now = new AtomicLong(1_000L);
        AlertWriter rateLimitedWriter = new AlertWriter(callbacks, now::get);
        String key = "text/html";
        String message = "Dropping because content-type 'text/html' is not instrumented";

        rateLimitedWriter.writeInfoRateLimited(key, message);
        rateLimitedWriter.writeInfoRateLimited(key, message);
        rateLimitedWriter.writeInfoRateLimited(key, message);

        verify(callbacks, times(1)).printOutput(message);
    }

    @Test
    void writeInfoRateLimited_logsSuppressedCountAfterWindow() {
        AtomicLong now = new AtomicLong(1_000L);
        AlertWriter rateLimitedWriter = new AlertWriter(callbacks, now::get);
        String key = "text/html";
        String message = "Dropping because content-type 'text/html' is not instrumented";

        rateLimitedWriter.writeInfoRateLimited(key, message);
        rateLimitedWriter.writeInfoRateLimited(key, message);
        rateLimitedWriter.writeInfoRateLimited(key, message);
        now.addAndGet(AlertWriter.RATE_LIMIT_WINDOW_MS);
        rateLimitedWriter.writeInfoRateLimited(key, message);

        verify(callbacks).printOutput(message);
        verify(callbacks).printOutput(message + " (2 similar messages suppressed)");
    }

    @Test
    void writeInfoRateLimited_doesNotRateLimitDifferentKeysTogether() {
        AtomicLong now = new AtomicLong(1_000L);
        AlertWriter rateLimitedWriter = new AlertWriter(callbacks, now::get);

        rateLimitedWriter.writeInfoRateLimited("text/html", "drop html");
        rateLimitedWriter.writeInfoRateLimited("text/css", "drop css");
        rateLimitedWriter.writeInfoRateLimited("text/html", "drop html");

        verify(callbacks, times(1)).printOutput("drop html");
        verify(callbacks, times(1)).printOutput("drop css");
    }

    @Test
    void writeInfo_isNotRateLimited() {
        alertWriter.writeInfo("same");
        alertWriter.writeInfo("same");
        alertWriter.writeInfo("same");

        verify(callbacks, times(3)).printOutput("same");
    }

    @Test
    void writeErrorRateLimited_logsFirstOccurrenceImmediately() {
        AtomicLong now = new AtomicLong(1_000L);
        AlertWriter rateLimitedWriter = new AlertWriter(callbacks, now::get);
        String message = "Cannot send HTTP message to Levo. Status code(401): unauthorized";

        rateLimitedWriter.writeErrorRateLimited("send-failed:401", message);

        verify(callbacks, times(1)).printError(message);
        verify(callbacks, never()).printOutput(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void writeErrorRateLimited_suppressesRepeatsWithinWindow() {
        AtomicLong now = new AtomicLong(1_000L);
        AlertWriter rateLimitedWriter = new AlertWriter(callbacks, now::get);
        String key = "send-failed:401";
        String message = "Cannot send HTTP message to Levo. Status code(401): unauthorized";

        rateLimitedWriter.writeErrorRateLimited(key, message);
        rateLimitedWriter.writeErrorRateLimited(key, message);
        rateLimitedWriter.writeErrorRateLimited(key, message);

        verify(callbacks, times(1)).printError(message);
        verify(callbacks, never()).printOutput(anyString());
    }

    @Test
    void writeErrorRateLimited_logsSuppressedCountAfterWindow() {
        AtomicLong now = new AtomicLong(1_000L);
        AlertWriter rateLimitedWriter = new AlertWriter(callbacks, now::get);
        String key = "send-failed:401";
        String message = "Cannot send HTTP message to Levo. Status code(401): unauthorized";

        rateLimitedWriter.writeErrorRateLimited(key, message);
        rateLimitedWriter.writeErrorRateLimited(key, message);
        rateLimitedWriter.writeErrorRateLimited(key, message);
        now.addAndGet(AlertWriter.RATE_LIMIT_WINDOW_MS);
        rateLimitedWriter.writeErrorRateLimited(key, message);

        verify(callbacks).printError(message);
        verify(callbacks).printError(message + " (2 similar messages suppressed)");
    }

    @Test
    void writeErrorRateLimited_doesNotRateLimitDifferentStatusCodesTogether() {
        AtomicLong now = new AtomicLong(1_000L);
        AlertWriter rateLimitedWriter = new AlertWriter(callbacks, now::get);

        rateLimitedWriter.writeErrorRateLimited("send-failed:401", "401");
        rateLimitedWriter.writeErrorRateLimited("send-failed:500", "500");
        rateLimitedWriter.writeErrorRateLimited("send-failed:401", "401");

        verify(callbacks, times(1)).printError("401");
        verify(callbacks, times(1)).printError("500");
    }

    @Test
    void writeError_isNotRateLimited() {
        alertWriter.writeError("same");
        alertWriter.writeError("same");
        alertWriter.writeError("same");

        verify(callbacks, times(3)).printError("same");
    }
}
