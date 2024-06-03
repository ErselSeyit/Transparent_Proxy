import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;

public class TransparentProxy {
    private ServerSocket serverSocket;
    private AtomicBoolean isRunning = new AtomicBoolean(false);
    private List<String> filterList = new CopyOnWriteArrayList<>();
    private static final Logger LOGGER = Logger.getLogger(TransparentProxy.class.getName());
    private ExecutorService executorService;
    private final int threadPoolSize;
    private final int httpPort;
    private final int httpsPort;
    private final ConcurrentHashMap<String, AtomicInteger> rateLimitMap = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, CachedResponse> cache = new ConcurrentHashMap<>();
    private final Map<String, List<String>> clientLogs = new ConcurrentHashMap<>();
    private final Map<String, Boolean> clientFilterStatus = new ConcurrentHashMap<>();
    private final String LOGIN_PAGE = "<html><body><h1>Login</h1><form method='POST' action='/login'>Token: <input type='text' name='token'><br><input type='submit' value='Submit'></form></body></html>";

    public class CachedResponse {
        private String body;
        private String lastModified;

        public CachedResponse(String body, String lastModified) {
            this.body = body;
            this.lastModified = lastModified;
        }

        public String getBody() {
            return body;
        }

        public String getLastModified() {
            return lastModified;
        }
    }

    public TransparentProxy() throws IOException {
        Properties properties = new Properties();
        try (FileInputStream fis = new FileInputStream("config.properties")) {
            properties.load(fis);
        } catch (FileNotFoundException e) {
            LOGGER.log(Level.SEVERE, "Configuration file not found", e);
            throw e;
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error loading configuration file", e);
            throw e;
        }

        this.threadPoolSize = Integer.parseInt(properties.getProperty("threadPoolSize"));
        this.httpPort = Integer.parseInt(properties.getProperty("httpPort"));
        this.httpsPort = Integer.parseInt(properties.getProperty("httpsPort"));
        serverSocket = new ServerSocket(Integer.parseInt(properties.getProperty("port")));
        executorService = Executors.newFixedThreadPool(threadPoolSize);
        validateConfiguration();
    }

    private void validateConfiguration() {
        if (threadPoolSize <= 0) {
            throw new IllegalArgumentException("Invalid thread pool size");
        }
        if (httpPort <= 0 || httpsPort <= 0) {
            throw new IllegalArgumentException("Invalid port numbers");
        }
        LOGGER.log(Level.INFO, "Configuration validated successfully");
    }

    public void start() {
        isRunning.set(true);
        while (isRunning.get()) {
            try {
                Socket clientSocket = serverSocket.accept();
                executorService.submit(() -> handleClient(clientSocket));
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Error accepting client connection", e);
            }
        }
    }

    public void stop() {
        isRunning.set(false);
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
        }
        try {
            serverSocket.close();
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error closing server socket", e);
        }
    }

    public void addHostToFilter(String host) {
        if (host != null && !host.isEmpty() && !filterList.contains(host)) {
            filterList.add(host);
            LOGGER.log(Level.INFO, "Added host to filter: " + host);
        }
    }

    public void removeHostFromFilter(String host) {
        filterList.remove(host);
        LOGGER.log(Level.INFO, "Removed host from filter: " + host);
    }

    public List<String> getFilteredHosts() {
        return filterList;
    }

    private void cacheResponse(String key, HttpResponse<String> response) {
        if (response.getHeaders().containsKey("Last-Modified")) {
            cache.put(key, new CachedResponse(response.getBody(), response.getHeaders().get("Last-Modified")));
            LOGGER.log(Level.INFO, "Cached response for URL: " + key);
        }
    }

    private HttpResponse<String> getCachedResponse(String key, String lastModifiedSince) {
        CachedResponse cachedResponse = cache.get(key);
        if (cachedResponse != null && cachedResponse.getLastModified().equals(lastModifiedSince)) {
            return new HttpResponse<>(304, cachedResponse.getBody(), Collections.singletonMap("Content-Type", "text/html"));
        }
        return null;
    }

    public HttpResponse<String> makeHttpRequest(String url) {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request;
        java.net.http.HttpResponse<String> standardResponse = null;
        HttpResponse<String> customResponse = null;

        try {
            request = HttpRequest.newBuilder()
                    .uri(new URI(url))
                    .header("If-Modified-Since", getLastModified(url))
                    .build();

            standardResponse = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());

            if (standardResponse != null) {
                Map<String, String> headers = standardResponse.headers().map()
                        .entrySet()
                        .stream()
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                e -> String.join(", ", e.getValue())
                        ));
                customResponse = new HttpResponse<>(
                        standardResponse.statusCode(),
                        standardResponse.body(),
                        headers
                );
                cacheResponse(url, customResponse);
            }
        } catch (URISyntaxException e) {
            LOGGER.log(Level.SEVERE, "Invalid URL: " + url, e);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "I/O error occurred when sending or receiving data", e);
        } catch (InterruptedException e) {
            LOGGER.log(Level.SEVERE, "Operation was interrupted", e);
            Thread.currentThread().interrupt();
        }

        return customResponse;
    }

    private String getLastModified(String url) {
        CachedResponse cachedResponse = cache.get(url);
        return cachedResponse != null ? cachedResponse.getLastModified() : "";
    }

    private void handleClient(Socket clientSocket) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String line = reader.readLine();
            if (line == null) {
                sendErrorResponse(clientSocket, 400); // Send a 400 Bad Request error
                return;
            }
    
            // Log the client's IP address and request
            String clientIp = clientSocket.getInetAddress().getHostAddress();
            LOGGER.log(Level.INFO, "Received request from " + clientIp + ": " + line);
            logRequest(clientIp, line);
    
            // Check rate limit
            rateLimitMap.putIfAbsent(clientIp, new AtomicInteger(0));
            if (rateLimitMap.get(clientIp).incrementAndGet() > 100) { // limit to 100 requests per minute per IP
                sendErrorResponse(clientSocket, 429); // Send a 429 Too Many Requests error
                return;
            }
    
            // Parse the request
            String[] parts = line.split(" ");
            String method = parts[0];
            String url = parts[1];
    
            // Handle login page
            if (url.equals("/login") && method.equals("POST")) {
                String requestBody = readRequestBody(reader);
                LOGGER.log(Level.INFO, "Login request body: " + requestBody); // Log the request body for debugging
                handleLoginRequest(clientSocket, requestBody, clientIp);
                return;
            }
    
            // Check if the client is logged in
            Boolean filterStatus = clientFilterStatus.get(clientIp);
            LOGGER.log(Level.INFO, "Client filter status for " + clientIp + ": " + filterStatus);
            if (filterStatus == null) {
                LOGGER.log(Level.INFO, "Client " + clientIp + " is not logged in. Sending login page.");
                sendLoginPage(clientSocket);
                return;
            }
    
            String host = extractHost(line);
    
            if (method.equals("CONNECT")) {
                handleHttpsRequest(clientSocket, host);
            } else {
                if (isValidMethod(method)) {
                    HttpResponse<String> cachedResponse = getCachedResponse(url, getLastModified(url));
                    if (cachedResponse != null) {
                        // Use cached response
                        LOGGER.log(Level.INFO, "Serving cached response for URL: " + url);
                        sendCachedResponse(clientSocket, cachedResponse);
                    } else {
                        forwardRequest(clientSocket, host, line, clientIp); // Pass clientIp to forwardRequest
                    }
                } else {
                    sendErrorResponse(clientSocket, 405); // Send a 405 Method Not Allowed error
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error handling client request", e);
            sendErrorResponse(clientSocket, 500); // Send a 500 Internal Server Error
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Error closing client socket", e);
            }
        }
    }
    
    
    
    
    private void logRequest(String clientIp, String request) {
        // Log the client's IP and the request
        LOGGER.log(Level.INFO, "Request from " + clientIp + ": " + request);

        // Store the log entry in the in-memory log storage
        clientLogs.computeIfAbsent(clientIp, k -> new ArrayList<>()).add("Request from " + clientIp + ": " + request);
    }

    private void sendLoginPage(Socket clientSocket) throws IOException {
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        out.println("HTTP/1.1 200 OK");
        out.println("Content-Type: text/html");
        out.println();
        out.println(LOGIN_PAGE);
    }

    private void sendCachedResponse(Socket clientSocket, HttpResponse<String> cachedResponse) throws IOException {
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        out.println("HTTP/1.1 " + cachedResponse.getStatusCode() + " " + getStatusText(cachedResponse.getStatusCode()));
        for (Map.Entry<String, String> header : cachedResponse.getHeaders().entrySet()) {
            out.println(header.getKey() + ": " + header.getValue());
        }
        out.println();
        out.println(cachedResponse.getBody());
    }

    private boolean isValidMethod(String method) {
        return method.equals("GET") || method.equals("HEAD") || method.equals("OPTIONS") || method.equals("POST");
    }

    private String extractHost(String request) {
        String[] lines = request.split("\r\n");
        for (String line : lines) {
            if (line.startsWith("Host:")) {
                return line.split(" ")[1];
            }
        }
        return null;
    }

    private void forwardRequest(Socket clientSocket, String host, String request, String clientIp) {
        LOGGER.log(Level.INFO, "Forwarding request to host: " + host);
        try (Socket serverSocket = new Socket(host, httpPort);
             PrintWriter out = new PrintWriter(serverSocket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
             PrintWriter clientOut = new PrintWriter(clientSocket.getOutputStream(), true)) {
            
            logRequest(clientIp, request);

            String filteredHost = extractHost(request);
            if (filterList.contains(filteredHost)) {
                sendErrorResponse(clientSocket, 401);
                return;
            }

            out.println(request);

            String line;
            StringBuilder responseBuilder = new StringBuilder();
            while ((line = in.readLine()) != null) {
                responseBuilder.append(line).append("\r\n");
            }
            String response = responseBuilder.toString();

            if (response.contains("Last-Modified")) {
                cacheResponse(host + request.split(" ")[1], new HttpResponse<>(200, response, null));
            }

            clientOut.println(response);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error forwarding request to host: " + host, e);
            sendErrorResponse(clientSocket, 502); // Send a 502 Bad Gateway error
        }
    }

    private void handleHttpsRequest(Socket clientSocket, String host) {
        try (PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {
            SSLSocketFactory factory;
            try {
                factory = getSSLSocketFactory();
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                LOGGER.log(Level.SEVERE, "Error creating SSLSocketFactory", e);
                return;
            }

            SSLSocket sslSocket = (SSLSocket) factory.createSocket(clientSocket, host, httpsPort, true);
            sslSocket.setUseClientMode(false);

            sslSocket.addHandshakeCompletedListener(event -> {
                try {
                    SSLSession session = event.getSession();
                    String sniHost = session.getPeerHost();

                    if (filterList.contains(sniHost)) {
                        throw new SSLHandshakeException("Host is blocked");
                    }
                } catch (SSLException ex) {
                    LOGGER.log(Level.SEVERE, "SSL Exception in handshake: " + ex.getMessage());
                }
            });

            sslSocket.startHandshake();
            forwardData(sslSocket, clientSocket);
            forwardData(clientSocket, sslSocket);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error handling HTTPS request", e);
            sendErrorResponse(clientSocket, 500); // Send a 500 Internal Server Error
        }
    }

    private SSLSocketFactory getSSLSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }}, new SecureRandom());
        return sslContext.getSocketFactory();
    }

    private void forwardData(Socket inputSocket, Socket outputSocket) {
        try (InputStream inputStream = inputSocket.getInputStream();
             OutputStream outputStream = outputSocket.getOutputStream()) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, read);
                outputStream.flush();
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error forwarding data", e);
        }
    }

    private void sendErrorResponse(Socket clientSocket, int statusCode) {
        try {
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            out.println("HTTP/1.1 " + statusCode + " " + getStatusText(statusCode));
            out.println("Content-Type: text/html");
            out.println();
            out.println("<h1>" + statusCode + " " + getStatusText(statusCode) + "</h1>");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error sending error response", e);
        }
    }

    private String getStatusText(int statusCode) {
        switch (statusCode) {
            case 401: return "Unauthorized";
            case 405: return "Method Not Allowed";
            case 429: return "Too Many Requests";
            case 502: return "Bad Gateway";
            default: return "Error";
        }
    }

    public void generateClientReport(String clientIp) throws IOException {
        List<String> reportLines = getClientLogs(clientIp);
        if (reportLines.isEmpty()) {
            LOGGER.log(Level.INFO, "No logs found for client IP: " + clientIp);
            return;
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(clientIp + "_report.txt"))) {
            for (String line : reportLines) {
                writer.write(line);
                writer.newLine();
            }
            LOGGER.log(Level.INFO, "Generated report for client IP: " + clientIp);
        }
    }

    private void handleLoginRequest(Socket clientSocket, String requestBody, String clientIp) throws IOException {
        String token = extractToken(requestBody);
        boolean filterStatus = false;
        boolean validToken = true;
    
        // Define valid tokens and their corresponding filter status
        Map<String, Boolean> validTokens = new HashMap<>();
        validTokens.put("8a21bce200", false); // Example token for no filtering
        validTokens.put("51e2cba401", true);  // Example token for enabling filtering
    
        LOGGER.log(Level.INFO, "Extracted token: " + token); // Log the extracted token for debugging
    
        if (validTokens.containsKey(token)) {
            filterStatus = validTokens.get(token);
            LOGGER.log(Level.INFO, "Client " + clientIp + " logged in with token " + token + " setting filter status to " + filterStatus);
            clientFilterStatus.put(clientIp, filterStatus);
        } else {
            validToken = false;
            LOGGER.log(Level.WARNING, "Client " + clientIp + " provided an invalid token " + token);
        }
    
        if (validToken) {
            sendLoginResponse(clientSocket, true);
        } else {
            sendLoginResponse(clientSocket, false);
        }
    }
    
    private String readRequestBody(BufferedReader reader) throws IOException {
        StringBuilder requestBody = new StringBuilder();
        String line;
        while (reader.ready() && (line = reader.readLine()) != null) {
            requestBody.append(line).append("\r\n");
        }
        LOGGER.log(Level.INFO, "Full request body: " + requestBody.toString().trim());
        return requestBody.toString().trim();
    }
    
    private static String extractToken(String requestBody) {
        if (requestBody == null || requestBody.isEmpty()) {
            LOGGER.log(Level.WARNING, "Empty or null request body");
            return "";
        }
    
        LOGGER.log(Level.INFO, "Request body before splitting: " + requestBody);
    
        String[] parts = requestBody.split("\r\n\r\n");
        requestBody = parts[parts.length - 1];
    
        LOGGER.log(Level.INFO, "Request body after splitting: " + requestBody);
    
        String[] pairs = requestBody.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length != 2) {
                LOGGER.log(Level.WARNING, "Invalid key-value pair: " + pair);
                continue;
            }
    
            String key = keyValue[0];
            String value = keyValue[1];
    
            LOGGER.log(Level.INFO, "Key: " + key + ", Value: " + value);
    
            if (key.equals("token")) {
                LOGGER.log(Level.INFO, "Found token: " + value);
                return value;
            }
        }
    
        LOGGER.log(Level.WARNING, "Token not found in request body");
        return "";
    }
    
    private void sendLoginResponse(Socket clientSocket, boolean success) throws IOException {
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        out.println("HTTP/1.1 " + (success ? "200 OK" : "401 Unauthorized"));
        out.println("Content-Type: text/html");
        out.println("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
        out.println("Cache-Control: post-check=0, pre-check=0");
        out.println("Pragma: no-cache");
        out.println();
        out.println("<html><body><h1>" + (success ? "Login Successful" : "Login Failed: Invalid Token") + "</h1></body></html>");
    }
    
    

    public Map<String, Boolean> getClientFilterStatus() {
        return clientFilterStatus;
    }

    private List<String> getClientLogs(String clientIp) {
        return clientLogs.getOrDefault(clientIp, Collections.emptyList());
    }

    public static class HttpResponse<T> {
        private int statusCode;
        private T body;
        private Map<String, String> headers;

        public HttpResponse(int statusCode, T body, Map<String, String> headers) {
            this.statusCode = statusCode;
            this.body = body;
            this.headers = headers;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public T getBody() {
            return body;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }
    }
}
