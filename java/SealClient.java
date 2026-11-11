import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;

public final class SealClient {

    private static final String API =
            System.getenv().getOrDefault("AURUM_API", "http://localhost:8787").replaceAll("/+$", "");

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private SealClient() {}

    static String digestOf(Path file) throws IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[1 << 16];
            int n;
            while ((n = in.read(buf)) != -1) {
                md.update(buf, 0, n);
            }
        }
        return HexFormat.of().formatHex(md.digest());
    }

    static String jsonString(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.append('"').toString();
    }

    static HttpResponse<String> send(HttpRequest request) throws IOException, InterruptedException {
        return HTTP.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    static int seal(Path file, String label) throws Exception {
        String body = "{\"digest\":" + jsonString(digestOf(file)) + ",\"label\":" + jsonString(label) + "}";
        HttpRequest request = HttpRequest.newBuilder(URI.create(API + "/api/seal"))
                .timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response = send(request);
        System.out.println(response.body());
        return response.statusCode() == 201 ? 0 : 1;
    }

    static int verify(Path file) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(API + "/api/verify/" + digestOf(file)))
                .timeout(Duration.ofSeconds(15))
                .GET()
                .build();
        HttpResponse<String> response = send(request);
        System.out.println(response.body());
        return response.statusCode() == 200 ? 0 : 1;
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: SealClient <hash|seal|verify> <file> [label]");
            System.exit(2);
        }
        Path file = Path.of(args[1]);
        if (!Files.isRegularFile(file)) {
            System.err.println("Not a file: " + args[1]);
            System.exit(2);
        }
        try {
            int code = switch (args[0]) {
                case "hash" -> {
                    System.out.println(digestOf(file));
                    yield 0;
                }
                case "seal" -> seal(file, args.length > 2 ? args[2] : file.getFileName().toString());
                case "verify" -> verify(file);
                default -> {
                    System.err.println("Unknown command: " + args[0]);
                    yield 2;
                }
            };
            System.exit(code);
        } catch (java.net.ConnectException e) {
            System.err.println("Cannot reach " + API);
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Failed: " + e.getMessage());
            System.exit(1);
        }
    }
}
