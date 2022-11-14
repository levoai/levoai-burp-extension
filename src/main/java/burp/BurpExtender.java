package burp;

import ai.levo.*;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

public class BurpExtender implements IBurpExtender {
    private static final String EXTENSION_NAME = "Levo.ai";
    private static IBurpExtenderCallbacks callbacks;
    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        ConfigMenu configMenu = null;
        JFrame burpFrame = ConfigMenu.getBurpFrame();
        try {
            callbacks.setExtensionName(EXTENSION_NAME);

            AlertWriter alertWriter = new AlertWriter(callbacks);

            // If the sending is not paused, ask the user if they want to continue sending the HTTP messages
            // or pause the sending.
            String satelliteUrl = callbacks.loadExtensionSetting(ConfigMenu.LEVO_SATELLITE_URL_CFG_KEY);
            if (satelliteUrl == null) {
                satelliteUrl = ConfigMenu.DEFAULT_LEVO_SATELLITE_URL;
            }

            boolean isSendingPaused = Boolean.parseBoolean(callbacks.loadExtensionSetting(ConfigMenu.ENABLE_SENDING_CFG_KEY));
            if (!isSendingPaused) {
                // Save the new URL of Levo's Satellite
                callbacks.saveExtensionSetting(ConfigMenu.LEVO_SATELLITE_URL_CFG_KEY, satelliteUrl);
            } else {
                callbacks.issueAlert("Sending traffic to Levo's Satellite is paused.");
            }

            // Init publisher and HTTP listener
            HttpMessagePublisher httpMessagePublisher =
                    new HttpMessagePublisher(LevoSatelliteService.create(satelliteUrl, callbacks), alertWriter, callbacks);
            HttpMessageListener httpListener = new HttpMessageListener(httpMessagePublisher, alertWriter, callbacks);

            // Set up the configuration menu
            configMenu = new ConfigMenu(callbacks, alertWriter);
            SwingUtilities.invokeLater(configMenu);

            // Register all listeners
            callbacks.registerHttpListener(httpListener);
            callbacks.registerExtensionStateListener(httpMessagePublisher);
            callbacks.registerExtensionStateListener(configMenu);
        } catch (Exception e) {
            String errMsg = "Cannot start the extension due to the following reason:\n\r" + e.getMessage();

            // Unload the menu if the extension cannot be loaded
            if (configMenu != null) {
                configMenu.extensionUnloaded();
            }

            // Notification of the error in the dashboard tab
            callbacks.issueAlert(errMsg);

            // Notification of the error using the UI
            JOptionPane.showMessageDialog(burpFrame, errMsg, EXTENSION_NAME, JOptionPane.ERROR_MESSAGE);
        }
    }
}
