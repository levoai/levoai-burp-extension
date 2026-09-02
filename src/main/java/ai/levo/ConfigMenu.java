package ai.levo;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Menu to configure the extension options.
 */
public class ConfigMenu implements Runnable, IExtensionStateListener {

    // Configuration menu names.
    private static final String EXTENSION_MENU_NAME = "Levo.ai";
    private static final String EXTENSION_MENU_TARGET_SCOPE_ONLY = "Send only traffic from defined target scope";
    private static final String EXTENSION_MENU_ENABLE_SEND = "Send traffic to Levo";
    private static final String EXTENSION_MENU_CONFIGURE_URL = "Set custom Levo's Satellite URL";
    private static final String EXTENSION_MENU_CONFIGURE_ORGANIZATION = "Set Levo Organization Id";
    private static final String EXTENSION_MENU_CONFIGURE_ENVIRONMENT = "Set Environment for Levo Dashboard";
    private static final String DEFAULT_LEVO_SATELLITE_URL = "https://satellite.levo.ai";

    /**
     * Expose the configuration option for the restriction of the sending of requests in defined target scope.
     */
    static volatile boolean ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.FALSE;

    /**
     * Expose the configuration option to allow the user to enable sending the traffic to Levo's Satellite.
     */
    static volatile boolean IS_SENDING_ENABLED = Boolean.FALSE;

    /**
     * Expose the configuration option to allow the user to configure Levo Satellite URL.
     */
    public static volatile String LEVO_SATELLITE_URL = DEFAULT_LEVO_SATELLITE_URL;


    /**
     * Expose the configuration option to allow the user to configure Levo Organization Id.
     */
    public static volatile String LEVO_ORGANIZATION_ID = null;

    /**
     * Expose the configuration option to allow the user to configure Levo environment
     */
    public static volatile String LEVO_ENVIRONMENT = null;


    /**
     * Option configuration key for the restriction of the sending of requests in defined target scope.
     */
    private static final String ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY = "ONLY_INCLUDE_REQUESTS_FROM_SCOPE";

    /**
     * Option configuration key to allow the user to start sending the traffic to Levo's Satellite.
     */
    public static final String ENABLE_SENDING_CFG_KEY = "ENABLE_SENDING";

    /**
     * Option configuration key to specify Levo's Satellite URL.
     */
    public static final String LEVO_SATELLITE_URL_CFG_KEY = "LEVO_SATELLITE_URL";

    /**
     * Option configuration key to specify Levo Organization ID.
     */
    public static final String LEVO_ORGANIZATION_ID_CFG_KEY = "LEVO_ORGANIZATION_ID";

    /**
     * Option configuration key to specify Levo Organization ID.
     */
    public static final String LEVO_ENVIRONMENT_CFG_KEY = "LEVO_ENVIRONMENT";

    /**
     * Extension root configuration menu.
     */
    private JMenu cfgMenu;

    /**
     * Ref on Burp tool to manipulate the HTTP requests and have access to API to identify the source of the
     * activity (tool name).
     */
    private final IBurpExtenderCallbacks callbacks;

    private final AlertWriter alertWriter;

    private final LevoSatelliteService levoSatelliteService;

    /**
     * Constructor.
     *
     * @param callbacks      Ref on Burp tool to manipulate the HTTP requests and have access to API to identify the
     *                       source of the activity (tool name).
     * @param alertWriter          Ref on alert writer.
     * @param levoSatelliteService Levo Satellite service
     */
    public ConfigMenu(IBurpExtenderCallbacks callbacks, AlertWriter alertWriter, LevoSatelliteService levoSatelliteService) {
        this.callbacks = callbacks;
        this.alertWriter = alertWriter;
        this.levoSatelliteService = levoSatelliteService;

        // Load the save state of the options
        String value = this.callbacks.loadExtensionSetting(LEVO_SATELLITE_URL_CFG_KEY);
        if (value != null || !value.isEmpty()) {
            LEVO_SATELLITE_URL = value;
        }
        LEVO_ORGANIZATION_ID = this.callbacks.loadExtensionSetting(LEVO_ORGANIZATION_ID_CFG_KEY);
        LEVO_ENVIRONMENT = this.callbacks.loadExtensionSetting(LEVO_ENVIRONMENT_CFG_KEY);
        value = this.callbacks.loadExtensionSetting(ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY);
        ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.parseBoolean(value);
        value = this.callbacks.loadExtensionSetting(ENABLE_SENDING_CFG_KEY);
        IS_SENDING_ENABLED = Boolean.parseBoolean(value);
    }

    /**
     * Build the options menu used to configure the extension.
     */
    @Override
    public void run() {
        this.cfgMenu = new JMenu(EXTENSION_MENU_NAME);

        this.cfgMenu.add(getConfigureOrganizationIdConfigMenuItem());
        this.cfgMenu.add(getConfigureEnvironmentConfigMenuItem());

        // Add the menu to enable sending the traffic
        final JCheckBoxMenuItem subMenuEnableSending =
                new JCheckBoxMenuItem(EXTENSION_MENU_ENABLE_SEND, IS_SENDING_ENABLED);
        subMenuEnableSending.addActionListener(new AbstractAction(EXTENSION_MENU_ENABLE_SEND) {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (subMenuEnableSending.isSelected()) {
                    String organizationId = callbacks.loadExtensionSetting(ConfigMenu.LEVO_ORGANIZATION_ID_CFG_KEY);
                    if (organizationId == null || organizationId.isEmpty()) {
                        JOptionPane.showMessageDialog(
                                getBurpFrame(),
                                "Please set the Levo Organization Id first.",
                                "Set Organization Id",
                                JOptionPane.INFORMATION_MESSAGE);
                        ConfigMenu.this.alertWriter.writeAlert("Please set the Levo Organization Id first.");
                        subMenuEnableSending.setSelected(false);
                        return;
                    }
                    String environment = callbacks.loadExtensionSetting(ConfigMenu.LEVO_ENVIRONMENT_CFG_KEY);
                    if (environment == null || environment.isEmpty()) {
                        JOptionPane.showMessageDialog(
                                getBurpFrame(),
                                "Environment not set. Using \'staging\' as default.",
                                "Set Environment",
                                JOptionPane.INFORMATION_MESSAGE);
                    }
                    ConfigMenu.this.callbacks.saveExtensionSetting(ENABLE_SENDING_CFG_KEY, Boolean.TRUE.toString());
                    ConfigMenu.IS_SENDING_ENABLED = Boolean.TRUE;
                    String satelliteUrl = callbacks.loadExtensionSetting(ConfigMenu.LEVO_SATELLITE_URL_CFG_KEY);
                    String msg = "Starting to send the traffic to Levo at address: " + satelliteUrl;
                    ConfigMenu.this.alertWriter.writeAlert(msg);
                } else {
                    ConfigMenu.this.callbacks.saveExtensionSetting(ENABLE_SENDING_CFG_KEY, Boolean.FALSE.toString());
                    ConfigMenu.IS_SENDING_ENABLED = Boolean.FALSE;
                    ConfigMenu.this.alertWriter.writeAlert("Stopped sending the traffic to Levo.");
                }
            }
        });
        this.cfgMenu.add(subMenuEnableSending);

        // Add the sub menu to restrict the sending of requests in defined target scope
        final JCheckBoxMenuItem subMenuRestrictToScope =
                new JCheckBoxMenuItem(EXTENSION_MENU_TARGET_SCOPE_ONLY, ONLY_INCLUDE_REQUESTS_FROM_SCOPE);

        subMenuRestrictToScope.addActionListener(new AbstractAction(EXTENSION_MENU_TARGET_SCOPE_ONLY) {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (subMenuRestrictToScope.isSelected()) {
                    ConfigMenu.this.callbacks.saveExtensionSetting(
                            ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY, Boolean.TRUE.toString());
                    ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.TRUE;
                    ConfigMenu.this.alertWriter.writeAlert(
                            "From now, only traffic from defined target scope will be sent to Levo.");
                } else {
                    ConfigMenu.this.callbacks.saveExtensionSetting(
                            ONLY_INCLUDE_REQUESTS_FROM_SCOPE_CFG_KEY, Boolean.FALSE.toString());
                    ConfigMenu.ONLY_INCLUDE_REQUESTS_FROM_SCOPE = Boolean.FALSE;
                    ConfigMenu.this.alertWriter.writeAlert(
                            "From now, traffic from all targets will be sent to Levo.");
                }
            }
        });
        this.cfgMenu.add(subMenuRestrictToScope);
        // Add the menu to change Levo's Satellite location
        this.cfgMenu.add(this.getConfigureSatelliteUrlConfigMenuItem());

        // Add it to BURP menu
        JFrame burpFrame = ConfigMenu.getBurpFrame();
        if (burpFrame != null) {
            JMenuBar jMenuBar = burpFrame.getJMenuBar();
            jMenuBar.add(this.cfgMenu);
            jMenuBar.repaint();
        } else {
            this.alertWriter.writeAlert("Cannot add Levo's configuration menu (ref on the BURP frame is null).");
        }
    }

    /**
     * Remove the menu from BURP menu bar.
     *
     * @see "https://github.com/PortSwigger/param-miner/blob/master/src/burp/Utilities.java"
     */
    @Override
    public void extensionUnloaded() {
        JFrame burpFrame = ConfigMenu.getBurpFrame();
        if (burpFrame != null && this.cfgMenu != null) {
            JMenuBar jMenuBar = burpFrame.getJMenuBar();
            jMenuBar.remove(this.cfgMenu);
            jMenuBar.repaint();
        } else {
            this.alertWriter.writeAlert("Cannot remove Levo's configuration menu (ref on the BURP frame is null).");
        }
    }

    private JMenuItem getConfigureSatelliteUrlConfigMenuItem() {
        final JMenuItem subMenuSatelliteUrlMenuItem = new JMenuItem(EXTENSION_MENU_CONFIGURE_URL);
        subMenuSatelliteUrlMenuItem.addActionListener(new AbstractAction(EXTENSION_MENU_CONFIGURE_URL) {
            @Override
            public void actionPerformed(ActionEvent e) {
                String satelliteUrl = callbacks.loadExtensionSetting(ConfigMenu.LEVO_SATELLITE_URL_CFG_KEY);
                try {
                    String title = EXTENSION_MENU_CONFIGURE_URL;
                    if (ConfigMenu.IS_SENDING_ENABLED) {
                        JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(),
                                "Sending must be paused prior to updating Levo's Satellite URL!",
                                title, JOptionPane.WARNING_MESSAGE);
                        return;
                    }

                    String msg = "Please enter the URL of Levo's Satellite:";
                    Object newSatelliteUrlInputResponse = JOptionPane.showInputDialog(getBurpFrame(), msg, title, JOptionPane.QUESTION_MESSAGE, null, null, satelliteUrl);
                    // Input response is null if the user cancels the dialog
                    if (newSatelliteUrlInputResponse == null) {
                        return;
                    }
                    String newSatelliteUrl = newSatelliteUrlInputResponse.toString();
                    if (newSatelliteUrl.isEmpty()) {
                        JOptionPane.showMessageDialog(
                                getBurpFrame(),
                                "Satellite URL can't be empty. Keeping current value: " + satelliteUrl,
                                title,
                                JOptionPane.INFORMATION_MESSAGE);
                        return;
                    }
                    // Validate the URL
                    new URL(newSatelliteUrl);
                    levoSatelliteService.updateSatelliteUrl(newSatelliteUrl);
                    callbacks.saveExtensionSetting(ConfigMenu.LEVO_SATELLITE_URL_CFG_KEY, newSatelliteUrl);
                    JOptionPane.showMessageDialog(
                            getBurpFrame(),
                            "Satellite URL changed to: " + newSatelliteUrl,
                            title,
                            JOptionPane.INFORMATION_MESSAGE);
                } catch (MalformedURLException exp) {
                    JOptionPane.showMessageDialog(
                            getBurpFrame(),
                            "Invalid URL format for Satellite URL. Keeping current value: " + satelliteUrl,
                            EXTENSION_MENU_CONFIGURE_URL,
                            JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception exp) {
                    ConfigMenu.this.alertWriter.writeAlert("Cannot update Satellite URL: " + exp.getMessage());
                }
            }
        });
        return subMenuSatelliteUrlMenuItem;
    }

    private JMenuItem getConfigureOrganizationIdConfigMenuItem() {
        final JMenuItem subMenuOrganizationIdMenuItem = new JMenuItem(EXTENSION_MENU_CONFIGURE_ORGANIZATION);
        subMenuOrganizationIdMenuItem.addActionListener(new AbstractAction(EXTENSION_MENU_CONFIGURE_ORGANIZATION) {
            @Override
            public void actionPerformed(ActionEvent e) {
                String organizationId = callbacks.loadExtensionSetting(ConfigMenu.LEVO_ORGANIZATION_ID_CFG_KEY);
                try {
                    String title = EXTENSION_MENU_CONFIGURE_ORGANIZATION;
                    if (ConfigMenu.IS_SENDING_ENABLED) {
                        JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(),
                                "Sending must be paused prior to updating organization id!",
                                title, JOptionPane.WARNING_MESSAGE);
                        return;
                    }

                    String msg = "Please enter your organization id:";
                    Object newOrganizationIdInputResponse = JOptionPane.showInputDialog(getBurpFrame(), msg, title, JOptionPane.QUESTION_MESSAGE, null, null, organizationId);
                    // Input response is null if the user cancels the dialog
                    if (newOrganizationIdInputResponse == null) {
                        return;
                    }
                    String newOrganizationId = newOrganizationIdInputResponse.toString();

                    levoSatelliteService.updateOrganizationId(newOrganizationId);
                    callbacks.saveExtensionSetting(ConfigMenu.LEVO_ORGANIZATION_ID_CFG_KEY, newOrganizationId);
                    JOptionPane.showMessageDialog(
                            getBurpFrame(),
                            "Organization id changed to: " + newOrganizationId,
                            title,
                            JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception exp) {
                    ConfigMenu.this.alertWriter.writeAlert("Cannot update Organization ID: " + exp.getMessage());
                }
            }
        });
        return subMenuOrganizationIdMenuItem;
    }

    private JMenuItem getConfigureEnvironmentConfigMenuItem() {
        final JMenuItem subMenuEnvironmentMenuItem = new JMenuItem(EXTENSION_MENU_CONFIGURE_ENVIRONMENT);
        subMenuEnvironmentMenuItem.addActionListener(new AbstractAction(EXTENSION_MENU_CONFIGURE_ENVIRONMENT) {
            @Override
            public void actionPerformed(ActionEvent e) {
                String environment = callbacks.loadExtensionSetting(ConfigMenu.LEVO_ENVIRONMENT_CFG_KEY);
                try {
                    String title = EXTENSION_MENU_CONFIGURE_ENVIRONMENT;
                    if (ConfigMenu.IS_SENDING_ENABLED) {
                        JOptionPane.showMessageDialog(ConfigMenu.getBurpFrame(),
                                "Sending must be paused prior to updating environment",
                                title, JOptionPane.WARNING_MESSAGE);
                        return;
                    }

                    String msg = "Please enter your environment:";
                    Object newEnvironmentInputResponse = JOptionPane.showInputDialog(getBurpFrame(), msg, title, JOptionPane.QUESTION_MESSAGE, null, null, environment);
                    // Input response is null if the user cancels the dialog
                    if (newEnvironmentInputResponse == null) {
                        return;
                    }
                    String newEnvironment = newEnvironmentInputResponse.toString();

                    levoSatelliteService.updateEnvironment(newEnvironment);
                    callbacks.saveExtensionSetting(ConfigMenu.LEVO_ENVIRONMENT_CFG_KEY, newEnvironment);
                    JOptionPane.showMessageDialog(
                            getBurpFrame(),
                            "Environment changed to: " + newEnvironment,
                            title,
                            JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception exp) {
                    ConfigMenu.this.alertWriter.writeAlert("Cannot update Environment: " + exp.getMessage());
                }
            }
        });
        return subMenuEnvironmentMenuItem;
    }

    /**
     * Get a reference on the BURP main frame.
     *
     * @return BURP main frame.
     * @see "https://github.com/PortSwigger/param-miner/blob/master/src/burp/Utilities.java"
     */
    public static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }

    // Create a dialog to update satellite url string
    private void updateSatelliteUrl(String satelliteUrl) {
        String title = EXTENSION_MENU_CONFIGURE_URL;
        String msg = "Please enter the URL of Levo's Satellite:";
        String newSatelliteUrl = JOptionPane.showInputDialog(getBurpFrame(), msg, title, JOptionPane.QUESTION_MESSAGE);
        if (newSatelliteUrl != null && !newSatelliteUrl.isEmpty()) {
            satelliteUrl = newSatelliteUrl;
        }
    }

}
