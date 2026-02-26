/*
 * MSJ — MonsterScan Java. Single combined module for crypto scanner logic.
 * On-chain registry for token and address scans; reporters submit risk scores and flags.
 * All outputs in one file: constants, exceptions, DTOs, engine, API handlers, validation.
 */

package contracts;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

// ============== Constants ==============

public final class MSJ {
    private MSJ() {}

    public static final int MSC_MAX_RISK_TIER = 10;
    public static final int MSC_MAX_SCANS = 50_000;
    public static final int MSC_BATCH_LIMIT = 64;
    public static final int MSC_VIEW_BATCH = 96;
    public static final int MSC_MAX_CATEGORIES = 16;
    public static final String MSC_SCAN_DOMAIN = sha256Hex("MonsterScan.MSC_SCAN_DOMAIN");
    public static final String MSC_REPORTER_ROLE = sha256Hex("MonsterScan.MSC_REPORTER_ROLE");
    public static final String MSC_TOKEN_NAMESPACE = sha256Hex("MonsterScan.MSC_TOKEN_NAMESPACE");

    public static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}

// ============== Exceptions ==============

class MSC_ZeroAddress extends RuntimeException { public MSC_ZeroAddress() { super("MSC_ZeroAddress"); } }
class MSC_ZeroScanId extends RuntimeException { public MSC_ZeroScanId() { super("MSC_ZeroScanId"); } }
class MSC_NotKeeper extends RuntimeException { public MSC_NotKeeper() { super("MSC_NotKeeper"); } }
class MSC_NotReporter extends RuntimeException { public MSC_NotReporter() { super("MSC_NotReporter"); } }
class MSC_NotVault extends RuntimeException { public MSC_NotVault() { super("MSC_NotVault"); } }
class MSC_ScanAlreadyExists extends RuntimeException { public MSC_ScanAlreadyExists() { super("MSC_ScanAlreadyExists"); } }
class MSC_ScanNotFound extends RuntimeException { public MSC_ScanNotFound() { super("MSC_ScanNotFound"); } }
class MSC_InvalidRiskTier extends RuntimeException { public MSC_InvalidRiskTier() { super("MSC_InvalidRiskTier"); } }
class MSC_AlreadyWhitelisted extends RuntimeException { public MSC_AlreadyWhitelisted() { super("MSC_AlreadyWhitelisted"); } }
class MSC_NotWhitelisted extends RuntimeException { public MSC_NotWhitelisted() { super("MSC_NotWhitelisted"); } }
class MSC_AlreadyBlacklisted extends RuntimeException { public MSC_AlreadyBlacklisted() { super("MSC_AlreadyBlacklisted"); } }
class MSC_NotBlacklisted extends RuntimeException { public MSC_NotBlacklisted() { super("MSC_NotBlacklisted"); } }
class MSC_ArrayLengthMismatch extends RuntimeException { public MSC_ArrayLengthMismatch() { super("MSC_ArrayLengthMismatch"); } }
class MSC_BatchTooLarge extends RuntimeException { public MSC_BatchTooLarge() { super("MSC_BatchTooLarge"); } }
class MSC_MaxScansReached extends RuntimeException { public MSC_MaxScansReached() { super("MSC_MaxScansReached"); } }
class MSC_InvalidCategory extends RuntimeException { public MSC_InvalidCategory() { super("MSC_InvalidCategory"); } }
class MSC_CategoryLimitReached extends RuntimeException { public MSC_CategoryLimitReached() { super("MSC_CategoryLimitReached"); } }
class MSC_ZeroToken extends RuntimeException { public MSC_ZeroToken() { super("MSC_ZeroToken"); } }
class MSC_ReporterAlreadyRegistered extends RuntimeException { public MSC_ReporterAlreadyRegistered() { super("MSC_ReporterAlreadyRegistered"); } }
class MSC_ReporterNotRegistered extends RuntimeException { public MSC_ReporterNotRegistered() { super("MSC_ReporterNotRegistered"); } }

// ============== DTOs ==============

final class ScanInfoDTO {
    final String scanId;
    final String target;
    final int riskTier;
    final String flagsHash;
    final String reporter;
    final long atBlock;
    final boolean exists;

    ScanInfoDTO(String scanId, String target, int riskTier, String flagsHash, String reporter, long atBlock, boolean exists) {
        this.scanId = scanId;
        this.target = target;
        this.riskTier = riskTier;
        this.flagsHash = flagsHash;
        this.reporter = reporter;
        this.atBlock = atBlock;
        this.exists = exists;
    }
}

final class TokenInfoDTO {
    final String tokenScanId;
    final String tokenAddress;
    final String symbolHash;
    final boolean registered;

    TokenInfoDTO(String tokenScanId, String tokenAddress, String symbolHash, boolean registered) {
        this.tokenScanId = tokenScanId;
        this.tokenAddress = tokenAddress;
        this.symbolHash = symbolHash;
        this.registered = registered;
    }
}

final class AddressStatusDTO {
    final boolean whitelisted;
    final boolean blacklisted;
    final int scanCount;

    AddressStatusDTO(boolean whitelisted, boolean blacklisted, int scanCount) {
        this.whitelisted = whitelisted;
        this.blacklisted = blacklisted;
        this.scanCount = scanCount;
    }
}

final class GlobalStatsDTO {
    final int totalScans;
    final int totalTokens;
    final int totalReporters;
    final int whitelistLen;
    final int blacklistLen;
    final long vaultBalance;

    GlobalStatsDTO(int totalScans, int totalTokens, int totalReporters, int whitelistLen, int blacklistLen, long vaultBalance) {
        this.totalScans = totalScans;
        this.totalTokens = totalTokens;
        this.totalReporters = totalReporters;
        this.whitelistLen = whitelistLen;
        this.blacklistLen = blacklistLen;
        this.vaultBalance = vaultBalance;
    }
}

// ============== Engine ==============

public final class MonsterScanEngine {
    private final String scannerKeeper;
    private final String reportVault;
    private final long deployBlock;
    private long currentBlock;
    private final Map<String, ScanInfoDTO> scans = new HashMap<>();
    private final List<String> scanIds = new ArrayList<>();
    private final Map<String, List<String>> targetScanIds = new HashMap<>();
    private final Set<String> whitelist = new HashSet<>();
    private final Set<String> blacklist = new HashSet<>();
    private final List<String> whitelistArr = new ArrayList<>();
    private final List<String> blacklistArr = new ArrayList<>();
    private final Set<String> reporters = new HashSet<>();
    private final Map<Integer, Long> riskThreshold = new HashMap<>();
    private final Map<String, String> tokenAddress = new HashMap<>();
    private final Set<String> tokenRegistered = new HashSet<>();
    private final List<String> tokenScanIds = new ArrayList<>();
    private final Map<String, Integer> scanCategory = new HashMap<>();
    private final Map<Integer, String> categoryName = new HashMap<>();
    private final Map<Integer, List<String>> categoryScanIds = new HashMap<>();
    private int categoryCount;
    private long vaultBalance;
    private boolean paused;

    @SuppressWarnings("unchecked")
    public MonsterScanEngine(String scannerKeeper, String reportVault, long deployBlock) {
        if (scannerKeeper == null || scannerKeeper.isEmpty()) throw new MSC_ZeroAddress();
        if (reportVault == null || reportVault.isEmpty()) throw new MSC_ZeroAddress();
        this.scannerKeeper = scannerKeeper;
        this.reportVault = reportVault;
        this.deployBlock = deployBlock;
        this.currentBlock = deployBlock;
        riskThreshold.put(1, 100L);
        riskThreshold.put(2, 200L);
        riskThreshold.put(3, 500L);
        riskThreshold.put(5, 1000L);
        riskThreshold.put(8, 2000L);
    }

    public void setBlock(long block) { this.currentBlock = block; }
    public long getBlock() { return currentBlock; }

    public int registerCategory(String nameHash, String caller) {
        if (!scannerKeeper.equals(caller)) throw new MSC_NotKeeper();
        if (categoryCount >= MSJ.MSC_MAX_CATEGORIES) throw new MSC_CategoryLimitReached();
        int id = categoryCount++;
        categoryName.put(id, nameHash);
        categoryScanIds.put(id, new ArrayList<>());
        return id;
    }

    public void registerToken(String tokenScanId, String token, String symbolHash, String caller) {
        if (!scannerKeeper.equals(caller)) throw new MSC_NotKeeper();
        if (token == null || token.isEmpty()) throw new MSC_ZeroToken();
        if (tokenScanId == null || tokenScanId.isEmpty()) throw new MSC_ZeroScanId();
        if (tokenRegistered.contains(tokenScanId)) throw new MSC_ScanAlreadyExists();
        if (tokenScanIds.size() >= MSJ.MSC_MAX_SCANS) throw new MSC_MaxScansReached();
        tokenRegistered.add(tokenScanId);
        tokenAddress.put(tokenScanId, token);
        tokenScanIds.add(tokenScanId);
    }

    public void submitScan(String scanId, String target, int riskTier, String flagsHash, String reporter) {
        submitScanWithCategory(scanId, target, riskTier, flagsHash, -1, reporter);
    }

    public void submitScanWithCategory(String scanId, String target, int riskTier, String flagsHash, int categoryId, String reporter) {
        if (paused) throw new RuntimeException("MSC_Paused");
        if (reporter == null || !reporters.contains(reporter)) throw new MSC_NotReporter();
        if (scanId == null || scanId.isEmpty()) throw new MSC_ZeroScanId();
        if (target == null || target.isEmpty()) throw new MSC_ZeroAddress();
        if (riskTier < 0 || riskTier > MSJ.MSC_MAX_RISK_TIER) throw new MSC_InvalidRiskTier();
        if (scans.containsKey(scanId)) throw new MSC_ScanAlreadyExists();
        if (scanIds.size() >= MSJ.MSC_MAX_SCANS) throw new MSC_MaxScansReached();
        if (categoryId >= 0 && categoryId >= categoryCount) throw new MSC_InvalidCategory();
        ScanInfoDTO info = new ScanInfoDTO(scanId, target, riskTier, flagsHash != null ? flagsHash : "", reporter, currentBlock, true);
        scans.put(scanId, info);
        scanIds.add(scanId);
        targetScanIds.computeIfAbsent(target, k -> new ArrayList<>()).add(scanId);
        if (categoryId >= 0) {
            scanCategory.put(scanId, categoryId);
            categoryScanIds.get(categoryId).add(scanId);
        }
    }

    public void addToWhitelist(String target, String caller) {
        if (!scannerKeeper.equals(caller)) throw new MSC_NotKeeper();
        if (target == null || target.isEmpty()) throw new MSC_ZeroAddress();
        if (whitelist.contains(target)) throw new MSC_AlreadyWhitelisted();
        whitelist.add(target);
        whitelistArr.add(target);
    }

    public void removeFromWhitelist(String target, String caller) {
        if (!scannerKeeper.equals(caller)) throw new MSC_NotKeeper();
        if (!whitelist.contains(target)) throw new MSC_NotWhitelisted();
        whitelist.remove(target);
        whitelistArr.remove(target);
    }

    public void addToBlacklist(String target, String caller) {
        if (!scannerKeeper.equals(caller)) throw new MSC_NotKeeper();
        if (target == null || target.isEmpty()) throw new MSC_ZeroAddress();
        if (blacklist.contains(target)) throw new MSC_AlreadyBlacklisted();
        blacklist.add(target);
        blacklistArr.add(target);
    }

    public void removeFromBlacklist(String target, String caller) {
        if (!scannerKeeper.equals(caller)) throw new MSC_NotKeeper();
        if (!blacklist.contains(target)) throw new MSC_NotBlacklisted();
        blacklist.remove(target);
        blacklistArr.remove(target);
    }

    public void setRiskThreshold(int riskTier, long value, String caller) {
        if (!scannerKeeper.equals(caller)) throw new MSC_NotKeeper();
        if (riskTier < 0 || riskTier > MSJ.MSC_MAX_RISK_TIER) throw new MSC_InvalidRiskTier();
        riskThreshold.put(riskTier, value);
    }

    public void registerReporter(String reporter, String caller) {
        if (!scannerKeeper.equals(caller)) throw new MSC_NotKeeper();
        if (reporter == null || reporter.isEmpty()) throw new MSC_ZeroAddress();
        if (reporters.contains(reporter)) throw new MSC_ReporterAlreadyRegistered();
        reporters.add(reporter);
    }

    public void revokeReporter(String reporter, String caller) {
        if (!scannerKeeper.equals(caller)) throw new MSC_NotKeeper();
        if (!reporters.contains(reporter)) throw new MSC_ReporterNotRegistered();
        reporters.remove(reporter);
    }

    public void pause() { paused = true; }
    public void unpause() { paused = false; }
    public boolean isPaused() { return paused; }

    public ScanInfoDTO getScan(String scanId) { return scans.get(scanId); }
    public boolean scanExists(String scanId) { return scans.containsKey(scanId); }
    public List<String> getScanIds() { return new ArrayList<>(scanIds); }
    public int targetScanCount(String target) { return targetScanIds.getOrDefault(target, Collections.emptyList()).size(); }
    public List<String> getTargetScanIds(String target) { return new ArrayList<>(targetScanIds.getOrDefault(target, Collections.emptyList())); }
    public boolean isWhitelisted(String target) { return whitelist.contains(target); }
    public boolean isBlacklisted(String target) { return blacklist.contains(target); }
    public boolean isReporter(String addr) { return reporters.contains(addr); }
    public long getRiskThreshold(int tier) { return riskThreshold.getOrDefault(tier, 0L); }
    public long getVaultBalance() { return vaultBalance; }
    public String getTokenAddress(String tokenScanId) { return tokenAddress.get(tokenScanId); }
    public boolean tokenRegistered(String tokenScanId) { return tokenRegistered.contains(tokenScanId); }
    public List<String> getTokenScanIds() { return new ArrayList<>(tokenScanIds); }
    public int getCategoryCount() { return categoryCount; }
    public String getCategoryName(int categoryId) { return categoryName.get(categoryId); }
    public int getCategoryScanCount(int categoryId) { return categoryScanIds.getOrDefault(categoryId, Collections.emptyList()).size(); }
    public List<String> getCategoryScanIds(int categoryId) { return new ArrayList<>(categoryScanIds.getOrDefault(categoryId, Collections.emptyList())); }
    public Integer getScanCategory(String scanId) { return scanCategory.get(scanId); }
    public String getScannerKeeper() { return scannerKeeper; }
    public String getReportVault() { return reportVault; }
    public long getDeployBlock() { return deployBlock; }
    public int scanCount() { return scanIds.size(); }
    public int reporterCount() { return reporters.size(); }
    public int tokenCount() { return tokenScanIds.size(); }
