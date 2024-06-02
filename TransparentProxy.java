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

    // In-memory log storage
    private final Map<String, List<String>> clientLogs = new ConcurrentHashMap<>();
    private final Map<String, Boolean> clientFilterStatus = new ConcurrentHashMap<>();

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

    public class HttpResponse<T> {
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

    public TransparentProxy() throws IOException {
        Properties properties = new Properties();
        properties.load(new FileInputStream("config.properties"));
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

    public Map<String, Boolean> getClientFilterStatus() {
        return clientFilterStatus;
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

            // Check if the client is already authenticated
            if (!clientFilterStatus.containsKey(clientIp)) {
                handleLoginRequest(clientSocket, clientIp, line);
                return;
            }

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

            String host = extractHost(url);

            if (method.equals("CONNECT")) {
                handleHttpsRequest(clientSocket, host, clientIp);
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
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Error closing client socket", e);
            }
        }
    }

    private void handleLoginRequest(Socket clientSocket, String clientIp, String request) {
        try (PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {
            out.println("HTTP/1.1 200 OK");
            out.println("Content-Type: text/html");
            out.println();
            out.println("<html><body>");
            out.println("<h1>Login</h1>");
            out.println("<form method='POST' action='/login'>");
            out.println("Token: <input type='text' name='token'><br>");
            out.println("<input type='submit' value='Submit'>");
            out.println("</form>");
            out.println("</body></html>");
            out.flush();

            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("POST /login")) {
                    char[] buffer = new char[1024];
                    reader.read(buffer);
                    String body = new String(buffer).trim();
                    String token = body.split("=")[1];

                    if ("8a21bce200".equals(token)) {
                        clientFilterStatus.put(clientIp, false);
                    } else if ("51e2cba401".equals(token)) {
                        clientFilterStatus.put(clientIp, true);
                    }
                    break;
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error handling login request", e);
        }
    }

    private void logRequest(String clientIp, String request) {
        // Log the client's IP and the request
        LOGGER.log(Level.INFO, "Request from " + clientIp + ": " + request);

        // Store the log entry in the in-memory log storage
        clientLogs.computeIfAbsent(clientIp, k -> new ArrayList<>()).add("Request from " + clientIp + ": " + request);
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

    private void forwardRequest(Socket clientSocket, String host, String request, String clientIp) throws IOException {
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
        }
    }

    private void handleHttpsRequest(Socket clientSocket, String host, String clientIp) {
        try (PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {
            SSLSocketFactory factory;
            try {
                factory = getSSLSocketFactory();
            } catch (NoSuchAlgorithmException | KeyManagementException e) {
                e.printStackTrace();
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

    private void sendErrorResponse(Socket clientSocket, int statusCode) throws IOException {
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        out.println("HTTP/1.1 " + statusCode + " " + getStatusText(statusCode));
        out.println("Content-Type: text/html");
        out.println();
        out.println("<h1>" + statusCode + " " + getStatusText(statusCode) + "</h1>");
    }

    private String getStatusText(int statusCode) {
        switch (statusCode) {
            case 401: return "Unauthorized";
            case 405: return "Method Not Allowed";
            case 429: return "Too Many Requests";
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

    private List<String> getClientLogs(String clientIp) {
        return clientLogs.getOrDefault(clientIp, Collections.emptyList());
    }
}
