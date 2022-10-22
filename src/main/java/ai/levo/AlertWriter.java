package ai.levo;

import burp.IBurpExtenderCallbacks;

/**
 * Write an alert into the BURP ALERT TAB.
 */
public class AlertWriter {

    /**
     * Ref on Burp tool to have access to the BURP ALERT TAB.
     */
    private final IBurpExtenderCallbacks callbacks;

    /**
     * Constructor.
     *
     * @param callbacks Ref on Burp tool to have access to the BURP ALERT TAB.
     */
    public AlertWriter(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    /**
     * Write the alert.
     *
     * @param message Message to write.
     */
    void writeAlert(String message) {
        this.callbacks.issueAlert(message);
    }
}
