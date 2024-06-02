import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ProxyGUI extends Application {
    private TransparentProxy proxy;
    private TextArea logArea;
    private ListView<String> filterListView;
    private ListView<String> clientStatusListView;
    private static final Logger LOGGER = Logger.getLogger(ProxyGUI.class.getName());

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Transparent Proxy");

        BorderPane root = new BorderPane();
        Scene scene = new Scene(root, 800, 600);

        // Menu Bar
        MenuBar menuBar = new MenuBar();
        Menu fileMenu = new Menu("File");
        MenuItem startItem = new MenuItem("Start");
        MenuItem stopItem = new MenuItem("Stop");
        MenuItem reportItem = new MenuItem("Report");
        MenuItem addFilterItem = new MenuItem("Add host to filter");
        MenuItem displayFilterItem = new MenuItem("Display current filtered hosts");
        MenuItem displayClientStatusItem = new MenuItem("Display client filter status");
        MenuItem exitItem = new MenuItem("Exit");

        fileMenu.getItems().addAll(startItem, stopItem, reportItem, addFilterItem, displayFilterItem, displayClientStatusItem, new SeparatorMenuItem(), exitItem);
        menuBar.getMenus().addAll(fileMenu);

        Menu helpMenu = new Menu("Help");
        MenuItem aboutItem = new MenuItem("About");
        helpMenu.getItems().add(aboutItem);
        menuBar.getMenus().add(helpMenu);

        root.setTop(menuBar);

        // Log Area
        logArea = new TextArea();
        logArea.setEditable(false);
        root.setCenter(logArea);

        // Filter List View
        filterListView = new ListView<>();
        VBox filterBox = new VBox(new Label("Filtered Hosts"), filterListView);
        root.setRight(filterBox);

        // Client Status List View
        clientStatusListView = new ListView<>();
        VBox clientStatusBox = new VBox(new Label("Client Filter Status"), clientStatusListView);
        root.setLeft(clientStatusBox);

        // Menu Actions
        startItem.setOnAction(e -> startProxy());
        stopItem.setOnAction(e -> stopProxy());
        addFilterItem.setOnAction(e -> addHostToFilter());
        displayFilterItem.setOnAction(e -> displayFilteredHosts());
        displayClientStatusItem.setOnAction(e -> displayClientStatus());
        exitItem.setOnAction(e -> Platform.exit());
        aboutItem.setOnAction(e -> showAbout());

        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void startProxy() {
        if (proxy == null) {
            try {
                proxy = new TransparentProxy();
                new Thread(() -> proxy.start()).start();
                logArea.appendText("Proxy started.\n");
            } catch (IOException ex) {
                logArea.appendText("Failed to start proxy: " + ex.getMessage() + "\n");
                LOGGER.log(Level.SEVERE, "Failed to start proxy", ex);
            }
        }
    }

    private void stopProxy() {
        if (proxy != null) {
            proxy.stop();
            proxy = null;
            logArea.appendText("Proxy stopped.\n");
        }
    }

    private void addHostToFilter() {
        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle("Add Host to Filter");
        dialog.setHeaderText("Add Host to Filter");
        dialog.setContentText("Please enter the host:");

        dialog.showAndWait().ifPresent(host -> {
            if (proxy != null) {
                proxy.addHostToFilter(host);
                logArea.appendText("Added host to filter: " + host + "\n");
                updateFilteredHosts();
            }
        });
    }

    private void displayFilteredHosts() {
        updateFilteredHosts();
        logArea.appendText("Displayed current filtered hosts.\n");
    }

    private void displayClientStatus() {
        updateClientStatus();
        logArea.appendText("Displayed client filter status.\n");
    }

    private void updateFilteredHosts() {
        if (proxy != null) {
            filterListView.getItems().clear();
            filterListView.getItems().addAll(proxy.getFilteredHosts());
        }
    }

    private void updateClientStatus() {
        if (proxy != null) {
            clientStatusListView.getItems().clear();
            proxy.getClientFilterStatus().forEach((clientIp, filterStatus) -> {
                String status = filterStatus ? "Enabled" : "Disabled";
                clientStatusListView.getItems().add(clientIp + ": " + status);
            });
        }
    }

    private void showAbout() {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("About");
        alert.setHeaderText("Transparent Proxy");
        alert.setContentText("Developer: Your Name");
        alert.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
