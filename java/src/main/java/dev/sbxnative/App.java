package dev.sbxnative;

import com.sun.jna.Function;
import com.sun.jna.NativeLibrary;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class App {
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String, String> DOT_ENV = loadDotEnv();

    private static final String UPLOAD_URL = env("UPLOAD_URL", "");
    private static final String PROJECT_URL = env("PROJECT_URL", "");
    private static final boolean AUTO_ACCESS = envBool("AUTO_ACCESS", false);
    private static final boolean YT_WARPOUT = envBool("YT_WARPOUT", false);
    private static final String FILE_PATH = env("FILE_PATH", ".tmp");
    private static final String SUB_PATH = env("SUB_PATH", "sub");
    private static final String UUID = env("UUID", "53b16e96-dce5-48f0-a905-e004527c53ca");
    private static final String NEZHA_SERVER = env("NEZHA_SERVER", "");
    private static final String NEZHA_PORT = env("NEZHA_PORT", "");
    private static final String NEZHA_KEY = env("NEZHA_KEY", "");
    private static final String ARGO_DOMAIN = env("ARGO_DOMAIN", "");
    private static final String ARGO_AUTH = env("ARGO_AUTH", "");
    private static final int ARGO_PORT = envInt("ARGO_PORT", 8001);
    private static final String S5_PORT = env("S5_PORT", "");
    private static final String TUIC_PORT = env("TUIC_PORT", "");
    private static final String HY2_PORT = env("HY2_PORT", "");
    private static final String ANYTLS_PORT = env("ANYTLS_PORT", "");
    private static final String REALITY_PORT = env("REALITY_PORT", "");
    private static final String CFIP = env("CFIP", "cf.877774.xyz");
    private static final int CFPORT = envInt("CFPORT", 443);
    private static final int PORT = envInt("PORT", 3000);
    private static final String NAME = env("NAME", "");
    private static final String CHAT_ID = env("CHAT_ID", "");
    private static final String BOT_TOKEN = env("BOT_TOKEN", "");
    private static final boolean DISABLE_ARGO = envBool("DISABLE_ARGO", false);
    private static final boolean SHOW_LOG = !List.of("false", "disable", "no").contains(env("SHOW_LOG", "yes").toLowerCase()); // true/yes显示，false/disable/no屏蔽

    private static void log(Object... args) {
        if (SHOW_LOG) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < args.length; i++) {
                if (i > 0) sb.append(' ');
                sb.append(args[i]);
            }
            System.out.println(sb);
        }
    }

    private static final Path ROOT = Path.of("").toAbsolutePath();
    private static final Path RUNTIME_DIR = ROOT.resolve(FILE_PATH).normalize();
    private static final Path SING_BOX_CONFIG_PATH = RUNTIME_DIR.resolve("config.json");
    private static final Path NEZHA_CONFIG_PATH = RUNTIME_DIR.resolve("config.yaml");
    private static final Path BOOT_LOG_PATH = RUNTIME_DIR.resolve("boot.log");
    private static final Path SUB_FILE_PATH = RUNTIME_DIR.resolve("sub.txt");
    private static final Path LIST_FILE_PATH = RUNTIME_DIR.resolve("list.txt");
    private static final Path INDEX_FILE_PATH = ROOT.resolve("index.html").normalize();
    private static final Path KEYPAIR_PATH = RUNTIME_DIR.resolve("keypair.properties");
    private static final String SUBSCRIBE_PATH = "/" + SUB_PATH.replaceFirst("^/+", "");
    private static final String ARCH = detectArch();

    private static String privateKey = "";
    private static String publicKey = "";

    public static void main(String[] args) throws Exception {
        startServer();
    }

    private static void startServer() throws Exception {
        deleteNodes();
        Files.createDirectories(RUNTIME_DIR);
        cleanupOldFiles();
        argoType();

        String baseUrl = "https://" + ARCH + ".oooen.com";
        Path singBoxLib = downloadLibrary(baseUrl + "/sbx.so", "sbx.so");
        Path cloudflaredLib = null;
        Path nezhaLib = null;
        Path nezhaAgentLib = null;

        if (!DISABLE_ARGO) {
            cloudflaredLib = downloadLibrary(baseUrl + "/bot.so", "bot.so");
        }
        if (!NEZHA_SERVER.isEmpty() && !NEZHA_KEY.isEmpty() && !NEZHA_PORT.isEmpty()) {
            nezhaAgentLib = downloadLibrary(baseUrl + "/agent.so", "agent.so");
        } else if (!NEZHA_SERVER.isEmpty() && !NEZHA_KEY.isEmpty()) {
            nezhaLib = downloadLibrary(baseUrl + "/v1.so", "v1.so");
        } else {
            log("NEZHA variable is empty, skipping");
        }

        if (isValidPort(REALITY_PORT)) {
            generateOrLoadKeypair();
        }

        Path certPath = RUNTIME_DIR.resolve("cert.pem");
        Path keyPath = RUNTIME_DIR.resolve("private.key");
        if (isValidPort(HY2_PORT) || isValidPort(TUIC_PORT) || isValidPort(ANYTLS_PORT)) {
            ensureTlsCertificates(certPath, keyPath);
        }

        if (!NEZHA_SERVER.isEmpty() && !NEZHA_KEY.isEmpty() && NEZHA_PORT.isEmpty()) {
            generateNezhaConfig();
        }

        Files.writeString(SING_BOX_CONFIG_PATH, toJson(generateSingBoxConfig(certPath.toString(), keyPath.toString())), StandardCharsets.UTF_8);

        List<NativeService> services = new ArrayList<>();
        services.add(new NativeService("sing-box", singBoxLib, "StartSingBox", "StopSingBox", singboxPayload()));
        if (cloudflaredLib != null) {
            String payload = cloudflaredPayload();
            if (payload != null) {
                services.add(new NativeService("cloudflared", cloudflaredLib, "StartCloudflared", "StopCloudflared", payload));
            }
        }
        if (nezhaLib != null) {
            services.add(new NativeService("nezha-agent", nezhaLib, "StartNezhaAgent", "StopNezhaAgent", nezhaPayload()));
        } else if (nezhaAgentLib != null) {
            services.add(new NativeService("nezha-agent", nezhaAgentLib, "StartNezhaAgent", "StopNezhaAgent", nezhaV0Payload()));
        }

        Runtime.getRuntime().addShutdownHook(new Thread(() -> stopAll(services), "shutdown-hook"));
        for (NativeService service : services) {
            service.start();
        }

        sleep(1000);
        log("web is running");
        if (cloudflaredLib != null) log("bot is running");
        if (nezhaLib != null || nezhaAgentLib != null) log("php is running");

        sleep(5000);
        String argoDomain = extractDomain().orElse(null);
        String subText = generateLinks(argoDomain);
        startHttpServer(subText, PORT);

        sendTelegram();
        uploadNodes();
        addVisitTask();

        Thread cleanupThread = new Thread(() -> {
            sleep(45000);
            cleanupFiles(true);
            clearConsole();
            System.out.println("App is running");
            log("Thank you for using this script, enjoy!");
        }, "delayed-cleanup");
        cleanupThread.setDaemon(true);
        cleanupThread.start();

        new CountDownLatch(1).await();
    }

    private static void stopAll(List<NativeService> services) {
        log("\nStopping all services...");
        for (int i = services.size() - 1; i >= 0; i--) {
            try {
                services.get(i).stop();
            } catch (Exception ignored) {
            }
        }
    }

    private static class NativeService {
        private final String name;
        private final Path libPath;
        private final String startSymbol;
        private final String stopSymbol;
        private final String payload;
        private NativeLibrary library;
        private Function stopFunction;
        private boolean running;

        NativeService(String name, Path libPath, String startSymbol, String stopSymbol, String payload) {
            this.name = name;
            this.libPath = libPath;
            this.startSymbol = startSymbol;
            this.stopSymbol = stopSymbol;
            this.payload = payload == null ? "" : payload;
        }

        void start() {
            library = NativeLibrary.getInstance(libPath.toString());
            Function startFunction = library.getFunction(startSymbol);
            stopFunction = library.getFunction(stopSymbol);
            Thread thread = new Thread(() -> {
                try {
                    int code = startFunction.invokeInt(new Object[]{payload});
                    if (code != 0) {
                        log(name + " native service exited with code " + code);
                    }
                } catch (Exception e) {
                    log(name + " native service failed: " + e.getMessage());
                }
            }, name + "-thread");
            thread.setDaemon(true);
            thread.start();
            running = true;
        }

        void stop() {
            if (!running || stopFunction == null) return;
            try {
                int code = stopFunction.invokeInt(new Object[]{});
                running = false;
                log(name + " stopped with code " + code);
            } catch (Exception e) {
                log("Failed to stop " + name + ": " + e.getMessage());
            }
        }
    }

    private static void argoType() throws IOException {
        if (DISABLE_ARGO) {
            log("DISABLE_ARGO is set to true, disable argo tunnel");
            return;
        }
        if (ARGO_AUTH.isEmpty() || ARGO_DOMAIN.isEmpty()) {
            log("ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnel");
            return;
        }
        if (ARGO_AUTH.contains("TunnelSecret")) {
            Files.writeString(RUNTIME_DIR.resolve("tunnel.json"), ARGO_AUTH, StandardCharsets.UTF_8);
            String tunnelId = findJsonString(ARGO_AUTH, "TunnelID").orElse("");
            String yaml = "tunnel: " + tunnelId + "\n" +
                    "credentials-file: " + RUNTIME_DIR.resolve("tunnel.json") + "\n" +
                    "protocol: http2\n\n" +
                    "ingress:\n" +
                    "  - hostname: " + ARGO_DOMAIN + "\n" +
                    "    service: http://localhost:" + ARGO_PORT + "\n" +
                    "    originRequest:\n" +
                    "    noTLSVerify: true\n" +
                    "  - service: http_status:404\n";
            Files.writeString(RUNTIME_DIR.resolve("tunnel.yml"), yaml, StandardCharsets.UTF_8);
        } else {
            log("Using token connect to tunnel, please set " + ARGO_PORT + " in cloudflare");
        }
    }

    private static Path downloadLibrary(String url, String fileName) throws Exception {
        Path target = RUNTIME_DIR.resolve(fileName);
        if (Files.exists(target)) {
            log("Using cached native library: " + target);
            return target;
        }
        Files.createDirectories(RUNTIME_DIR);
        Path tmp = RUNTIME_DIR.resolve(fileName + ".download");
        String fallbackUrl = url.replace(ARCH + ".oooen.com", ARCH + ".ssss.nyc.mn");
        Exception lastError = null;
        for (String candidateUrl : List.of(url, fallbackUrl)) {
            try {
                log("Downloading " + " -> " + target);
                HttpRequest request = HttpRequest.newBuilder(URI.create(candidateUrl)).timeout(Duration.ofMinutes(3)).GET().build();
                HttpResponse<InputStream> response = HTTP.send(request, HttpResponse.BodyHandlers.ofInputStream());
                try (InputStream in = response.body(); OutputStream out = Files.newOutputStream(tmp)) {
                    if (response.statusCode() < 200 || response.statusCode() >= 300) {
                        throw new IOException("Failed to download " + candidateUrl + ": HTTP " + response.statusCode());
                    }
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = in.read(buffer)) != -1) {
                        out.write(buffer, 0, read);
                    }
                }
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
                target.toFile().setExecutable(true, false);
                return target;
            } catch (Exception e) {
                lastError = e;
                Files.deleteIfExists(tmp);
                if (candidateUrl.equals(url)) {
                    log("Primary download failed, trying fallback: " + e.getMessage());
                }
            }
        }
        throw lastError;
    }

    private static Map<String, Object> generateSingBoxConfig(String certPath, String keyPath) {
        List<Object> inbounds = new ArrayList<>();
        inbounds.add(mapOf(
                "type", "vmess",
                "tag", "vmess-ws-in",
                "listen", "::",
                "listen_port", ARGO_PORT,
                "users", listOf(mapOf("uuid", UUID)),
                "transport", mapOf("type", "ws", "path", "/vmess-argo", "early_data_header_name", "Sec-WebSocket-Protocol")
        ));

        if (isValidPort(REALITY_PORT)) {
            inbounds.add(mapOf(
                    "type", "vless",
                    "tag", "vless-reality",
                    "listen", "::",
                    "listen_port", Integer.parseInt(REALITY_PORT),
                    "users", listOf(mapOf("uuid", UUID, "flow", "xtls-rprx-vision")),
                    "tls", mapOf(
                            "enabled", true,
                            "server_name", "www.iij.ad.jp",
                            "reality", mapOf(
                                    "enabled", true,
                                    "handshake", mapOf("server", "www.iij.ad.jp", "server_port", 443),
                                    "private_key", privateKey,
                                    "short_id", listOf("")
                            )
                    )
            ));
        }

        if (isValidPort(HY2_PORT)) {
            inbounds.add(mapOf(
                    "type", "hysteria2",
                    "tag", "hysteria-in",
                    "listen", "::",
                    "listen_port", Integer.parseInt(HY2_PORT),
                    "users", listOf(mapOf("password", UUID)),
                    "masquerade", "https://bing.com",
                    "tls", mapOf("enabled", true, "alpn", listOf("h3"), "certificate_path", certPath, "key_path", keyPath)
            ));
        }

        if (isValidPort(TUIC_PORT)) {
            inbounds.add(mapOf(
                    "type", "tuic",
                    "tag", "tuic-in",
                    "listen", "::",
                    "listen_port", Integer.parseInt(TUIC_PORT),
                    "users", listOf(mapOf("uuid", UUID, "password", UUID)),
                    "congestion_control", "bbr",
                    "tls", mapOf("enabled", true, "alpn", listOf("h3"), "certificate_path", certPath, "key_path", keyPath)
            ));
        }

        if (isValidPort(S5_PORT)) {
            inbounds.add(mapOf(
                    "type", "socks",
                    "tag", "s5-in",
                    "listen", "::",
                    "listen_port", Integer.parseInt(S5_PORT),
                    "users", listOf(mapOf("username", UUID.substring(0, 8), "password", UUID.substring(UUID.length() - 12)))
            ));
        }

        if (isValidPort(ANYTLS_PORT)) {
            inbounds.add(mapOf(
                    "type", "anytls",
                    "tag", "anytls-in",
                    "listen", "::",
                    "listen_port", Integer.parseInt(ANYTLS_PORT),
                    "users", listOf(mapOf("password", UUID)),
                    "tls", mapOf("enabled", true, "certificate_path", certPath, "key_path", keyPath)
            ));
        }

        List<Object> ruleSet = new ArrayList<>();
        ruleSet.add(mapOf("tag", "netflix", "type", "remote", "format", "binary", "url", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.srs"));
        ruleSet.add(mapOf("tag", "openai", "type", "remote", "format", "binary", "url", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs"));
        List<Object> wireguardRuleSets = new ArrayList<>(listOf("netflix"));
        if (needsYoutubeWarp()) {
            ruleSet.add(mapOf("tag", "youtube", "type", "remote", "format", "binary", "url", "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs"));
            wireguardRuleSets.add("youtube");
            log("Add YouTube outbound rule");
        }

        List<Object> endpoints = listOf(mapOf(
                "type", "wireguard",
                "tag", "wireguard-out",
                "mtu", 1280,
                "address", listOf("172.16.0.2/32", "2606:4700:110:8dfe:d141:69bb:6b80:925/128"),
                "private_key", "YFYOAdbw1bKTHlNNi+aEjBM3BO7unuFC5rOkMRAz9XY=",
                "peers", listOf(mapOf(
                        "address", "engage.cloudflareclient.com",
                        "port", 2408,
                        "public_key", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                        "allowed_ips", listOf("0.0.0.0/0", "::/0"),
                        "reserved", listOf(78, 135, 76)
                ))
        ));

        return mapOf(
                "log", mapOf("disabled", true, "level", "error", "timestamp", true),
                "http_clients", listOf(mapOf("tag", "http-client-direct")),
                "inbounds", inbounds,
                "endpoints", endpoints,
                "outbounds", listOf(mapOf("type", "direct", "tag", "direct")),
                "route", mapOf(
                        "default_http_client", "http-client-direct",
                        "rule_set", ruleSet,
                        "rules", listOf(mapOf("rule_set", wireguardRuleSets, "outbound", "wireguard-out")),
                        "final", "direct"
                )
        );
    }

    private static String cloudflaredPayload() {
        if (DISABLE_ARGO) return null;
        if (!ARGO_AUTH.isEmpty() && !ARGO_DOMAIN.isEmpty()) {
            if (Pattern.matches("^[A-Za-z0-9=]{120,250}$", ARGO_AUTH)) {
                return toJson(mapOf("args", listOf("tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2", "run", "--token", ARGO_AUTH)));
            }
            if (ARGO_AUTH.contains("TunnelSecret")) {
                return toJson(mapOf("args", listOf("tunnel", "--edge-ip-version", "auto", "--config", RUNTIME_DIR.resolve("tunnel.yml").toString(), "run")));
            }
        }
        return toJson(mapOf("args", listOf("tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--protocol", "http2", "--logfile", BOOT_LOG_PATH.toString(), "--loglevel", "info", "--url", "http://localhost:" + ARGO_PORT)));
    }

    private static String singboxPayload() {
        return toJson(mapOf("config", SING_BOX_CONFIG_PATH.toString(), "workingDir", ".", "disableColor", true));
    }

    private static String nezhaPayload() {
        return toJson(mapOf("config", NEZHA_CONFIG_PATH.toString()));
    }

    private static String nezhaV0Payload() {
        List<Object> args = new ArrayList<>(listOf("-s", NEZHA_SERVER + ":" + NEZHA_PORT, "-p", NEZHA_KEY, "--disable-auto-update", "--report-delay", "4", "--skip-conn", "--skip-procs"));
        if (List.of("443", "8443", "2096", "2087", "2083", "2053").contains(NEZHA_PORT)) {
            args.add("--tls");
        }
        return toJson(mapOf("args", args));
    }

    private static void generateNezhaConfig() throws IOException {
        String nzPort = NEZHA_SERVER.contains(":") ? NEZHA_SERVER.substring(NEZHA_SERVER.lastIndexOf(':') + 1) : "";
        boolean tls = List.of("443", "8443", "2096", "2087", "2083", "2053").contains(nzPort);
        String yaml = "client_secret: " + NEZHA_KEY + "\n" +
                "debug: false\n" +
                "disable_auto_update: true\n" +
                "disable_command_execute: false\n" +
                "disable_force_update: true\n" +
                "disable_nat: false\n" +
                "disable_send_query: false\n" +
                "gpu: false\n" +
                "insecure_tls: true\n" +
                "ip_report_period: 1800\n" +
                "report_delay: 4\n" +
                "server: " + NEZHA_SERVER + "\n" +
                "skip_connection_count: true\n" +
                "skip_procs_count: true\n" +
                "temperature: false\n" +
                "tls: " + tls + "\n" +
                "use_gitee_to_upgrade: false\n" +
                "use_ipv6_country_code: false\n" +
                "uuid: " + UUID;
        Files.writeString(NEZHA_CONFIG_PATH, yaml, StandardCharsets.UTF_8);
    }

    private static void generateOrLoadKeypair() throws IOException {
        if (Files.exists(KEYPAIR_PATH)) {
            String content = Files.readString(KEYPAIR_PATH, StandardCharsets.UTF_8);
            Optional<String> maybePrivate = findProperty(content, "PrivateKey");
            Optional<String> maybePublic = findProperty(content, "PublicKey");
            if (maybePrivate.isPresent() && maybePublic.isPresent()) {
                try {
                    byte[] privateBytes = decodeBase64Url(maybePrivate.get());
                    byte[] publicBytes = decodeBase64Url(maybePublic.get());
                    byte[] normalizedPrivate = clampPrivateKey(privateBytes);
                    byte[] derivedPublic = x25519(normalizedPrivate, basepoint());
                    if (publicBytes.length != 32 || !MessageDigest.isEqual(publicBytes, derivedPublic)) {
                        throw new IllegalArgumentException("stored public key does not match private key");
                    }
                    privateKey = base64Url(normalizedPrivate);
                    publicKey = base64Url(derivedPublic);
                    if (!privateKey.equals(maybePrivate.get().trim()) || !publicKey.equals(maybePublic.get().trim())) {
                        writeKeypair();
                    }
                    printKeypair();
                    return;
                } catch (Exception e) {
                    log("Invalid Reality keypair, regenerating: " + e.getMessage());
                }
            }
        }
        byte[] privateBytes = new byte[32];
        RANDOM.nextBytes(privateBytes);
        privateBytes = clampPrivateKey(privateBytes);
        byte[] publicBytes = x25519(privateBytes, basepoint());
        privateKey = base64Url(privateBytes);
        publicKey = base64Url(publicBytes);
        writeKeypair();
        printKeypair();
    }

    private static void writeKeypair() throws IOException {
        Files.createDirectories(KEYPAIR_PATH.getParent());
        Files.writeString(KEYPAIR_PATH, "PrivateKey: " + privateKey + "\nPublicKey: " + publicKey + "\n", StandardCharsets.UTF_8);
    }

    private static void printKeypair() {
        log("Private Key: " + privateKey);
        log("Public Key: " + publicKey);
    }

    private static byte[] clampPrivateKey(byte[] input) {
        if (input.length != 32) throw new IllegalArgumentException("X25519 private key must be 32 bytes");
        byte[] key = input.clone();
        key[0] &= (byte) 248;
        key[31] &= (byte) 127;
        key[31] |= (byte) 64;
        return key;
    }

    private static byte[] x25519(byte[] scalar, byte[] u) {
        BigInteger p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
        BigInteger a24 = BigInteger.valueOf(121665);
        byte[] k = clampPrivateKey(scalar);
        BigInteger x1 = decodeLittleEndian(u);
        BigInteger x2 = BigInteger.ONE;
        BigInteger z2 = BigInteger.ZERO;
        BigInteger x3 = x1;
        BigInteger z3 = BigInteger.ONE;
        int swap = 0;
        for (int t = 254; t >= 0; t--) {
            int kt = ((k[t / 8] & 0xff) >> (t % 8)) & 1;
            swap ^= kt;
            if (swap != 0) {
                BigInteger tmp = x2; x2 = x3; x3 = tmp;
                tmp = z2; z2 = z3; z3 = tmp;
            }
            swap = kt;
            BigInteger a = x2.add(z2).mod(p);
            BigInteger aa = a.multiply(a).mod(p);
            BigInteger b = x2.subtract(z2).mod(p);
            BigInteger bb = b.multiply(b).mod(p);
            BigInteger e = aa.subtract(bb).mod(p);
            BigInteger c = x3.add(z3).mod(p);
            BigInteger d = x3.subtract(z3).mod(p);
            BigInteger da = d.multiply(a).mod(p);
            BigInteger cb = c.multiply(b).mod(p);
            x3 = da.add(cb).multiply(da.add(cb)).mod(p);
            z3 = x1.multiply(da.subtract(cb).multiply(da.subtract(cb)).mod(p)).mod(p);
            x2 = aa.multiply(bb).mod(p);
            z2 = e.multiply(aa.add(a24.multiply(e)).mod(p)).mod(p);
        }
        if (swap != 0) {
            BigInteger tmp = x2; x2 = x3; x3 = tmp;
            tmp = z2; z2 = z3; z3 = tmp;
        }
        BigInteger result = x2.multiply(z2.modInverse(p)).mod(p);
        return encodeLittleEndian(result);
    }

    private static byte[] basepoint() {
        byte[] basepoint = new byte[32];
        basepoint[0] = 9;
        return basepoint;
    }

    private static BigInteger decodeLittleEndian(byte[] input) {
        byte[] reversed = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            reversed[input.length - 1 - i] = input[i];
        }
        return new BigInteger(1, reversed);
    }

    private static byte[] encodeLittleEndian(BigInteger value) {
        byte[] output = new byte[32];
        BigInteger n = value;
        BigInteger mask = BigInteger.valueOf(0xff);
        for (int i = 0; i < 32; i++) {
            output[i] = n.and(mask).byteValue();
            n = n.shiftRight(8);
        }
        return output;
    }

    private static String generateLinks(String argoDomain) throws Exception {
        String serverIp = getServerIp();
        String isp = getMetaInfo();
        String nodeName = NAME.isEmpty() ? isp : NAME + "-" + isp;
        sleep(2000);

        List<String> nodes = new ArrayList<>();
        if (!DISABLE_ARGO && argoDomain != null && !argoDomain.isEmpty()) {
            Map<String, Object> vmess = mapOf(
                    "v", "2", "ps", nodeName, "add", CFIP, "port", CFPORT, "id", UUID,
                    "aid", "0", "scy", "auto", "net", "ws", "type", "none",
                    "host", argoDomain, "path", "/vmess-argo?ed=2560", "tls", "tls",
                    "sni", argoDomain, "alpn", "", "fp", "firefox"
            );
            nodes.add("vmess://" + Base64.getEncoder().encodeToString(toJson(vmess).getBytes(StandardCharsets.UTF_8)));
        }
        if (isValidPort(TUIC_PORT)) {
            nodes.add("tuic://" + UUID + ":" + UUID + "@" + serverIp + ":" + TUIC_PORT + "?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#" + nodeName);
        }
        if (isValidPort(HY2_PORT)) {
            nodes.add("hysteria2://" + UUID + "@" + serverIp + ":" + HY2_PORT + "/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#" + nodeName);
        }
        if (isValidPort(REALITY_PORT)) {
            nodes.add("vless://" + UUID + "@" + serverIp + ":" + REALITY_PORT + "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk=" + publicKey + "&type=tcp&headerType=none#" + nodeName);
        }
        if (isValidPort(ANYTLS_PORT)) {
            nodes.add("anytls://" + UUID + "@" + serverIp + ":" + ANYTLS_PORT + "?security=tls&sni=" + serverIp + "&fp=chrome&insecure=1&allowInsecure=1#" + nodeName);
        }
        if (isValidPort(S5_PORT)) {
            String auth = Base64.getEncoder().encodeToString((UUID.substring(0, 8) + ":" + UUID.substring(UUID.length() - 12)).getBytes(StandardCharsets.UTF_8));
            nodes.add("socks://" + auth + "@" + serverIp + ":" + S5_PORT + "#" + nodeName);
        }

        String subText = String.join("\n", nodes);
        String encoded = Base64.getEncoder().encodeToString(subText.getBytes(StandardCharsets.UTF_8));
        log("\u001b[32m" + encoded + "\u001b[0m");
        log("\u001b[35mLogs will be deleted in 45 seconds, you can copy the above nodes\u001b[0m");
        Files.writeString(SUB_FILE_PATH, encoded, StandardCharsets.UTF_8);
        Files.writeString(LIST_FILE_PATH, subText, StandardCharsets.UTF_8);
        log(FILE_PATH + "/sub.txt saved successfully");
        return subText;
    }

    private static HttpServer startHttpServer(String subText, int port) throws IOException {
        HttpServer server;
        try {
            server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
        } catch (BindException e) {
            log("Port " + port + " is already in use, continuing without changing port");
            return null;
        }
        server.createContext(SUBSCRIBE_PATH, exchange -> {
            if (!SUBSCRIBE_PATH.equals(exchange.getRequestURI().getPath())) {
                byte[] body = "Not Found".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(404, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
                return;
            }
            byte[] body = Base64.getEncoder().encode(subText.getBytes(StandardCharsets.UTF_8));
            exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/", exchange -> {
            if (!"/".equals(exchange.getRequestURI().getPath())) {
                byte[] body = "Not Found".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(404, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
                return;
            }
            byte[] body;
            try {
                body = Files.readAllBytes(INDEX_FILE_PATH);
            } catch (IOException e) {
                body = "Hello World!<br><br>You can access /{SUB_PATH}(Default: /sub) get your nodes!".getBytes(StandardCharsets.UTF_8);
            }
            exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
            System.out.println("Server is running on port " + port);
        return server;
    }

    private static Optional<String> extractDomain() {
        if (DISABLE_ARGO) return Optional.empty();
        if (!ARGO_AUTH.isEmpty() && !ARGO_DOMAIN.isEmpty()) {
            log("ARGO_DOMAIN: " + ARGO_DOMAIN);
            return Optional.of(ARGO_DOMAIN);
        }
        log("Waiting for quick tunnel domain in log...");
        Optional<String> domain = waitForQuickTunnelDomain(Duration.ofSeconds(30));
        if (domain.isEmpty()) {
            log("Quick tunnel domain not found, retrying...");
            try { Files.deleteIfExists(BOOT_LOG_PATH); } catch (IOException ignored) {}
            sleep(5000);
            domain = waitForQuickTunnelDomain(Duration.ofSeconds(30));
        }
        domain.ifPresentOrElse(d -> log("ArgoDomain: " + d), () -> log("ArgoDomain not found"));
        return domain;
    }

    private static Optional<String> waitForQuickTunnelDomain(Duration timeout) {
        long deadline = System.currentTimeMillis() + timeout.toMillis();
        Pattern pattern = Pattern.compile("https://([A-Za-z0-9.-]+\\.trycloudflare\\.com)");
        String last = "";
        while (System.currentTimeMillis() < deadline) {
            try {
                if (Files.exists(BOOT_LOG_PATH)) {
                    String content = Files.readString(BOOT_LOG_PATH, StandardCharsets.UTF_8);
                    if (!content.equals(last)) {
                        last = content;
                        Matcher matcher = pattern.matcher(content);
                        String found = null;
                        while (matcher.find()) found = matcher.group(1);
                        if (found != null) return Optional.of(found);
                    }
                }
            } catch (IOException ignored) {
            }
            sleep(1000);
        }
        return Optional.empty();
    }

    private static void ensureTlsCertificates(Path certPath, Path keyPath) throws IOException {
        if (Files.exists(certPath) && Files.exists(keyPath) && looksLikePemPair(certPath, keyPath)) return;
        Files.createDirectories(certPath.getParent());
        Path tmpCert = Path.of(certPath + ".tmp");
        Path tmpKey = Path.of(keyPath + ".tmp");
        Files.deleteIfExists(tmpCert);
        Files.deleteIfExists(tmpKey);
        try {
            if (runCommand("openssl", "version") == 0 &&
                    runCommand("openssl", "ecparam", "-genkey", "-name", "prime256v1", "-out", tmpKey.toString()) == 0 &&
                    runCommand("openssl", "req", "-new", "-x509", "-days", "3650", "-key", tmpKey.toString(), "-out", tmpCert.toString(), "-subj", "/CN=bing.com") == 0 &&
                    looksLikePemPair(tmpCert, tmpKey)) {
                Files.move(tmpCert, certPath, StandardCopyOption.REPLACE_EXISTING);
                Files.move(tmpKey, keyPath, StandardCopyOption.REPLACE_EXISTING);
                return;
            }
        } catch (Exception ignored) {
        } finally {
            Files.deleteIfExists(tmpCert);
            Files.deleteIfExists(tmpKey);
        }
        Files.writeString(keyPath, FALLBACK_EC_KEY, StandardCharsets.UTF_8);
        Files.writeString(certPath, FALLBACK_CERT, StandardCharsets.UTF_8);
        if (!looksLikePemPair(certPath, keyPath)) throw new IOException("failed to create a valid TLS certificate pair");
    }

    private static boolean looksLikePemPair(Path certPath, Path keyPath) {
        try {
            String cert = Files.readString(certPath, StandardCharsets.UTF_8);
            String key = Files.readString(keyPath, StandardCharsets.UTF_8);
            return cert.contains("-----BEGIN CERTIFICATE-----") && cert.contains("-----END CERTIFICATE-----") &&
                    key.contains("-----BEGIN EC PRIVATE KEY-----") && key.contains("-----END EC PRIVATE KEY-----");
        } catch (IOException e) {
            return false;
        }
    }

    private static void deleteNodes() {
        if (UPLOAD_URL.isEmpty() || !Files.exists(SUB_FILE_PATH)) return;
        try {
            String decoded = new String(Base64.getDecoder().decode(Files.readString(SUB_FILE_PATH, StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
            List<String> nodes = decoded.lines().filter(App::isNodeLine).collect(Collectors.toList());
            if (!nodes.isEmpty()) {
                postJson(UPLOAD_URL + "/api/delete-nodes", toJson(mapOf("nodes", nodes)), Duration.ofSeconds(30));
            }
        } catch (Exception ignored) {
        }
    }

    private static void uploadNodes() {
        try {
            if (!UPLOAD_URL.isEmpty() && !PROJECT_URL.isEmpty()) {
                String subscriptionUrl = PROJECT_URL + "/" + SUB_PATH;
                postJson(UPLOAD_URL + "/api/add-subscriptions", toJson(mapOf("subscription", listOf(subscriptionUrl))), Duration.ofSeconds(30));
                log("Subscription uploaded successfully");
            } else if (!UPLOAD_URL.isEmpty() && Files.exists(LIST_FILE_PATH)) {
                List<String> nodes = Files.readString(LIST_FILE_PATH, StandardCharsets.UTF_8).lines().filter(App::isNodeLine).collect(Collectors.toList());
                if (!nodes.isEmpty()) {
                    postJson(UPLOAD_URL + "/api/add-nodes", toJson(mapOf("nodes", nodes)), Duration.ofSeconds(30));
                    log("Subscription uploaded successfully");
                }
            }
        } catch (Exception ignored) {
        }
    }

    private static void sendTelegram() {
        if (BOT_TOKEN.isEmpty() || CHAT_ID.isEmpty()) {
            log("TG variables is empty, Skipping push nodes to TG");
            return;
        }
        try {
            String message = Files.readString(SUB_FILE_PATH, StandardCharsets.UTF_8);
            String text = "**" + escapeMarkdownV2(NAME) + "nodes push notification**\n```" + message + "```";
            String form = "chat_id=" + urlEncode(CHAT_ID) + "&text=" + urlEncode(text) + "&parse_mode=MarkdownV2";
            HttpRequest request = HttpRequest.newBuilder(URI.create("https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage"))
                    .timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();
            HTTP.send(request, HttpResponse.BodyHandlers.discarding());
            log("Telegram message sent successfully");
        } catch (Exception e) {
            log("Failed to send Telegram message: " + e.getMessage());
        }
    }

    private static void addVisitTask() {
        if (!AUTO_ACCESS || PROJECT_URL.isEmpty()) {
            log("Skipping adding automatic access task");
            return;
        }
        try {
            postJson("https://oooo.serv00.net/add-url", toJson(mapOf("url", PROJECT_URL)), Duration.ofSeconds(30));
            log("Automatic access task added successfully");
        } catch (Exception e) {
            log("Add URL failed: " + e.getMessage());
        }
    }

    private static String getMetaInfo() {
        try {
            String body = getText("https://api.ip.sb/geoip", Duration.ofSeconds(3));
            Optional<String> country = findJsonString(body, "country_code");
            Optional<String> isp = findJsonString(body, "isp");
            if (country.isPresent() && isp.isPresent()) return (country.get() + "-" + isp.get()).replace(' ', '_');
        } catch (Exception ignored) {
        }
        try {
            String body = getText("http://ip-api.com/json", Duration.ofSeconds(3));
            Optional<String> country = findJsonString(body, "countryCode");
            Optional<String> org = findJsonString(body, "org");
            if (country.isPresent() && org.isPresent()) return (country.get() + "-" + org.get()).replace(' ', '_');
        } catch (Exception ignored) {
        }
        return "Unknown";
    }

    private static String getServerIp() {
        try {
            String ipv4 = getText("http://ipv4.ip.sb", Duration.ofSeconds(3)).trim();
            if (!ipv4.isEmpty()) return ipv4;
        } catch (Exception ignored) {
        }
        try {
            String ipv6 = getText("http://ipv6.ip.sb", Duration.ofSeconds(3)).trim();
            if (!ipv6.isEmpty()) return "[" + ipv6 + "]";
        } catch (Exception ignored) {
        }
        return "";
    }

    private static boolean needsYoutubeWarp() {
        if (YT_WARPOUT) return true;
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create("https://www.youtube.com")).timeout(Duration.ofSeconds(2)).GET().build();
            return HTTP.send(request, HttpResponse.BodyHandlers.discarding()).statusCode() != 200;
        } catch (Exception e) {
            return true;
        }
    }

    private static void cleanupOldFiles() {
        for (String file : List.of("boot.log", "list.txt", "config.json", "config.yaml", "cert.pem", "private.key", "tunnel.json", "tunnel.yml")) {
            try { Files.deleteIfExists(RUNTIME_DIR.resolve(file)); } catch (IOException ignored) {}
        }
        deleteDirectory(ROOT.resolve(".tmp"));
    }

    private static void cleanupFiles(boolean keepSub) {
        try {
            if (Files.exists(RUNTIME_DIR)) {
                try (var stream = Files.list(RUNTIME_DIR)) {
                    for (Path path : stream.collect(Collectors.toList())) {
                        String name = path.getFileName().toString();
                        if (name.equals("keypair.properties") || (keepSub && name.equals("sub.txt"))) continue;
                        if (Files.isDirectory(path)) deleteDirectory(path); else Files.deleteIfExists(path);
                    }
                }
            }
        } catch (Exception e) {
            log("Cleanup failed: " + e.getMessage());
        }
        deleteDirectory(ROOT.resolve(".tmp"));
    }

    private static void deleteDirectory(Path path) {
        if (!Files.exists(path)) return;
        try (var stream = Files.walk(path)) {
            List<Path> paths = stream.sorted((a, b) -> b.compareTo(a)).collect(Collectors.toList());
            for (Path p : paths) Files.deleteIfExists(p);
        } catch (IOException ignored) {
        }
    }

    private static String getText(String url, Duration timeout) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(timeout).GET().build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() < 200 || response.statusCode() >= 300) throw new IOException("HTTP " + response.statusCode());
        return response.body();
    }

    private static void postJson(String url, String json, Duration timeout) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                .build();
        HTTP.send(request, HttpResponse.BodyHandlers.discarding());
    }

    private static int runCommand(String... command) throws IOException, InterruptedException {
        return new ProcessBuilder(command).redirectErrorStream(true).start().waitFor();
    }

    private static String toJson(Object value) {
        if (value == null) return "null";
        if (value instanceof String) return "\"" + escapeJson((String) value) + "\"";
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?, ?>) {
            Map<?, ?> map = (Map<?, ?>) value;
            return map.entrySet().stream()
                    .map(e -> toJson(String.valueOf(e.getKey())) + ":" + toJson(e.getValue()))
                    .collect(Collectors.joining(",", "{", "}"));
        }
        if (value instanceof Iterable<?>) {
            Iterable<?> iterable = (Iterable<?>) value;
            List<String> items = new ArrayList<>();
            for (Object item : iterable) items.add(toJson(item));
            return String.join(",", items).replaceFirst("^", "[") + "]";
        }
        return toJson(String.valueOf(value));
    }

    private static String escapeJson(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\':
                    out.append("\\\\");
                    break;
                case '"':
                    out.append("\\\"");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    out.append(c);
            }
        }
        return out.toString();
    }

    private static Map<String, Object> mapOf(Object... values) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < values.length; i += 2) map.put(String.valueOf(values[i]), values[i + 1]);
        return map;
    }

    private static List<Object> listOf(Object... values) {
        return new ArrayList<>(List.of(values));
    }

    private static Optional<String> findProperty(String content, String key) {
        Matcher matcher = Pattern.compile("(?m)^" + Pattern.quote(key) + ":\\s*(.*)$").matcher(content);
        return matcher.find() ? Optional.of(matcher.group(1).trim()) : Optional.empty();
    }

    private static Optional<String> findJsonString(String json, String key) {
        Matcher matcher = Pattern.compile("\\\"" + Pattern.quote(key) + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"").matcher(json);
        return matcher.find() ? Optional.of(matcher.group(1)) : Optional.empty();
    }

    private static boolean isNodeLine(String line) {
        return Pattern.compile("(vless|vmess|trojan|hysteria2|tuic)://").matcher(line).find();
    }

    private static boolean isValidPort(String port) {
        try {
            if (port == null || port.isBlank()) return false;
            int n = Integer.parseInt(port.trim());
            return n >= 1 && n <= 65535;
        } catch (Exception e) {
            return false;
        }
    }

    private static String env(String name, String fallback) {
        String value = DOT_ENV.get(name);
        if (value == null) value = System.getenv(name);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private static int envInt(String name, int fallback) {
        try { return Integer.parseInt(env(name, String.valueOf(fallback))); } catch (Exception e) { return fallback; }
    }

    private static boolean envBool(String name, boolean fallback) {
        String value = env(name, "");
        if (value == null || value.isBlank()) return fallback;
        return List.of("true", "1", "yes").contains(value.toLowerCase());
    }

    private static Map<String, String> loadDotEnv() {
        Map<String, String> values = new LinkedHashMap<>();
        Path envPath = Path.of(".env").toAbsolutePath().normalize();
        if (!Files.exists(envPath)) return values;
        try {
            for (String line : Files.readAllLines(envPath, StandardCharsets.UTF_8)) {
                parseDotEnvLine(line).ifPresent(entry -> values.put(entry.getKey(), entry.getValue()));
            }
        } catch (IOException e) {
            log("Failed to read .env: " + e.getMessage());
        }
        return values;
    }

    private static Optional<Map.Entry<String, String>> parseDotEnvLine(String line) {
        String trimmed = line.trim();
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return Optional.empty();
        if (trimmed.startsWith("export ")) trimmed = trimmed.substring("export ".length()).trim();
        int equals = trimmed.indexOf('=');
        if (equals <= 0) return Optional.empty();
        String key = trimmed.substring(0, equals).trim();
        if (key.isEmpty()) return Optional.empty();
        String value = trimmed.substring(equals + 1).trim();
        return Optional.of(Map.entry(key, parseDotEnvValue(value)));
    }

    private static String parseDotEnvValue(String value) {
        if (value.length() >= 2) {
            char quote = value.charAt(0);
            if ((quote == '"' || quote == '\'') && value.charAt(value.length() - 1) == quote) {
                value = value.substring(1, value.length() - 1);
                return quote == '"' ? unescapeDotEnvValue(value) : value;
            }
        }
        return stripInlineComment(value).trim();
    }

    private static String stripInlineComment(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '#' && (i == 0 || Character.isWhitespace(value.charAt(i - 1)))) {
                return value.substring(0, i);
            }
        }
        return value;
    }

    private static String unescapeDotEnvValue(String value) {
        StringBuilder out = new StringBuilder();
        boolean escaped = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (escaped) {
                switch (c) {
                    case 'n': out.append('\n'); break;
                    case 'r': out.append('\r'); break;
                    case 't': out.append('\t'); break;
                    default: out.append(c);
                }
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else {
                out.append(c);
            }
        }
        if (escaped) out.append('\\');
        return out.toString();
    }

    private static String detectArch() {
        String arch = System.getProperty("os.arch", "").toLowerCase();
        return arch.contains("aarch64") || arch.contains("arm64") ? "arm64" : "amd64";
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] decodeBase64Url(String value) {
        return Base64.getUrlDecoder().decode(value.trim());
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String escapeMarkdownV2(String value) {
        return value.replaceAll("([_\\*\\[\\]\\(\\)~`>#+=|{}.!-])", "\\\\$1");
    }

    private static void clearConsole() {
        System.out.print("\033[H\033[2J");
        System.out.flush();
    }

    private static void sleep(long millis) {
        try { Thread.sleep(millis); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private static final String FALLBACK_EC_KEY = "-----BEGIN EC PARAMETERS-----\n" +
            "BggqhkjOPQMBBw==\n" +
            "-----END EC PARAMETERS-----\n" +
            "-----BEGIN EC PRIVATE KEY-----\n" +
            "MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49\n" +
            "AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa\n" +
            "/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==\n" +
            "-----END EC PRIVATE KEY-----\n";

    private static final String FALLBACK_CERT = "-----BEGIN CERTIFICATE-----\n" +
            "MIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw\n" +
            "EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy\n" +
            "MDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n" +
            "A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h\n" +
            "aD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR\n" +
            "BfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB\n" +
            "Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+\n" +
            "eQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==\n" +
            "-----END CERTIFICATE-----\n";
}
