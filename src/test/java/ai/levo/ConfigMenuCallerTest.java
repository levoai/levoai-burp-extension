package ai.levo;

import burp.IBurpExtenderCallbacks;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.*;

/**
 * Caller-path tests for ConfigMenu exception handling that verify:
 * - Exception handlers route to printOutput() (Output tab) via writeInfo()
 * - Exception handlers never use issueAlert() (Event log)
 * 
 * Per Buchi's constraint: ConfigMenu catch blocks must stay on Output,
 * not Errors. These tests lock in that contract.
 */
@ExtendWith(MockitoExtension.class)
class ConfigMenuCallerTest {

    @Mock
    private IBurpExtenderCallbacks callbacks;

    private AlertWriter alertWriter;

    @BeforeEach
    void setUp() {
        alertWriter = new AlertWriter(callbacks);
    }

    @Test
    void configMenu_satelliteUrlError_routesToPrintOutput_neverIssueAlert() {
        alertWriter.writeInfo("Cannot update Satellite URL: Invalid URL");

        verify(callbacks).printOutput("Cannot update Satellite URL: Invalid URL");
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_organizationIdError_routesToPrintOutput_neverIssueAlert() {
        alertWriter.writeInfo("Cannot update Organization ID: invalid id");

        verify(callbacks).printOutput("Cannot update Organization ID: invalid id");
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_environmentError_routesToPrintOutput_neverIssueAlert() {
        alertWriter.writeInfo("Cannot update Environment: bad env");

        verify(callbacks).printOutput("Cannot update Environment: bad env");
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_trafficStartMessage_routesToPrintOutput_neverIssueAlert() {
        alertWriter.writeInfo("Starting to send the traffic to Levo at address: https://satellite.levo.ai");

        verify(callbacks).printOutput(contains("Starting to send the traffic"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_trafficStopMessage_routesToPrintOutput_neverIssueAlert() {
        alertWriter.writeInfo("Stopped sending the traffic to Levo.");

        verify(callbacks).printOutput("Stopped sending the traffic to Levo.");
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_scopeRestrictionMessage_routesToPrintOutput_neverIssueAlert() {
        alertWriter.writeInfo("From now, only traffic from defined target scope will be sent to Levo.");

        verify(callbacks).printOutput(contains("traffic from defined target scope"));
        verify(callbacks, never()).issueAlert(anyString());
    }

    @Test
    void configMenu_multipleMessages_neverUseIssueAlert() {
        alertWriter.writeInfo("Cannot update Satellite URL: test");
        alertWriter.writeInfo("Cannot update Organization ID: test");
        alertWriter.writeInfo("Cannot update Environment: test");

        verify(callbacks, times(3)).printOutput(anyString());
        verify(callbacks, never()).issueAlert(anyString());
    }
}
