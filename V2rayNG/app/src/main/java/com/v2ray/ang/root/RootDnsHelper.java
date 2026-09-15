package com.v2ray.ang.root;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AtomicFile;
import com.v2ray.ang.AppConfig;
import dalvik.system.PathClassLoader;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.util.Arrays;

/** Root-only app_process entry point. The daemon owns stdin; EOF restores its DNS lease and routes. */
public final class RootDnsHelper {
    private static final String DESCRIPTOR = "android.net.IDnsResolver";
    private static final int TRANSACTION_SET_CONFIGURATION = 3;
    private static final int TRANSACTION_GET_INFO = 4;
    private static final int TRANSACTION_GET_VERSION = 16777215;
    private final IBinder resolver;
    private final Class<?> paramsClass;
    private final AtomicFile journal;
    private JSONArray leases;

    private RootDnsHelper(File directory) throws Exception {
        resolver = (IBinder) Class.forName("android.os.ServiceManager")
                .getMethod("getService", String.class).invoke(null, "dnsresolver");
        if (resolver == null || !DESCRIPTOR.equals(resolver.getInterfaceDescriptor())) {
            throw new IllegalStateException("Unsupported DNS resolver service");
        }
        int version;
        Parcel request = Parcel.obtain(), reply = Parcel.obtain();
        try {
            request.writeInterfaceToken(DESCRIPTOR);
            if (!resolver.transact(TRANSACTION_GET_VERSION, request, reply, 0)) throw new IllegalStateException("Unversioned DNS resolver");
            reply.readException();
            version = reply.readInt();
        } finally { request.recycle(); reply.recycle(); }
        // Android 10–16 stable IDnsResolver versions retain transactions 3 and 4. Use the
        // installed module's Parcelable layout (including vendor fields), never hand-encode it.
        // Revisit this adapter when the platform exposes a supported per-network DNS API.
        if (version < 2 || version > 17) throw new IllegalStateException("Unsupported DNS resolver version " + version);
        ClassLoader loader = new PathClassLoader(
                "/apex/com.android.tethering/javalib/service-connectivity.jar", getClass().getClassLoader());
        Class<?> found = null;
        for (String name : new String[]{"android.net.connectivity.android.net.ResolverParamsParcel", "android.net.ResolverParamsParcel"}) {
            try { found = Class.forName(name, true, loader); break; }
            catch (ClassNotFoundException ignored) { /* Explicit unsupported status below. */ }
        }
        if (found == null) throw new IllegalStateException("DNS Parcelable unavailable");
        paramsClass = found;
        journal = new AtomicFile(new File(directory, "dns-lease.json"));
        leases = journal.getBaseFile().exists()
                ? new JSONArray(new String(journal.readFully(), java.nio.charset.StandardCharsets.UTF_8)) : new JSONArray();
    }

    private JSONObject info(int netId) throws Exception {
        Parcel request = Parcel.obtain(), reply = Parcel.obtain();
        try {
            request.writeInterfaceToken(DESCRIPTOR);
            request.writeInt(netId);
            for (int count : new int[]{8, 8, 8, 6, 56, 1}) request.writeInt(count);
            if (!resolver.transact(TRANSACTION_GET_INFO, request, reply, 0)) throw new IllegalStateException("getResolverInfo unsupported");
            reply.readException();
            String[] servers = clean(reply.createStringArray());
            String[] domains = clean(reply.createStringArray());
            String[] tlsServers = clean(reply.createStringArray());
            int[] params = reply.createIntArray();
            reply.createIntArray(); reply.createIntArray();
            if (reply.dataAvail() != 0 || params == null || params.length != 6) {
                throw new IllegalStateException("Unexpected DNS resolver wire layout");
            }
            return new JSONObject().put("netId", netId).put("servers", new JSONArray(servers))
                    .put("domains", new JSONArray(domains)).put("tlsServers", new JSONArray(tlsServers))
                    .put("params", new JSONArray(params));
        } finally { request.recycle(); reply.recycle(); }
    }

    private static String[] clean(String[] values) {
        if (values == null) return new String[0];
        return Arrays.stream(values).filter(value -> value != null && !value.isEmpty()).toArray(String[]::new);
    }

    private static String[] strings(JSONArray array) throws Exception {
        String[] values = new String[array.length()];
        for (int i = 0; i < values.length; i++) values[i] = array.getString(i);
        return values;
    }

    private void field(Object parcel, String name, Object value, boolean required) throws Exception {
        try { Field field = paramsClass.getField(name); field.set(parcel, value); }
        catch (NoSuchFieldException e) { if (required) throw e; }
    }

    private void configure(JSONObject saved, String[] servers) throws Exception {
        Object params = paramsClass.getDeclaredConstructor().newInstance();
        field(params, "netId", saved.getInt("netId"), true);
        String[] names = {"sampleValiditySeconds", "successThreshold", "minSamples", "maxSamples", "baseTimeoutMsec", "retryCount"};
        for (int i = 0; i < names.length; i++) field(params, names[i], saved.getJSONArray("params").getInt(i), true);
        field(params, "servers", servers, true);
        field(params, "domains", strings(saved.getJSONArray("domains")), true);
        field(params, "tlsName", "", true);
        field(params, "tlsServers", new String[0], true);
        field(params, "tlsFingerprints", new String[0], false);
        field(params, "caCertificate", "", false);
        // Null leaves existing OEM resolver options intact in resolv_set_nameservers().
        field(params, "resolverOptions", null, false);
        JSONArray transports = saved.getJSONArray("transports");
        int[] transportTypes = new int[transports.length()];
        for (int i = 0; i < transportTypes.length; i++) transportTypes[i] = transports.getInt(i);
        field(params, "transportTypes", transportTypes, false);
        field(params, "meteredNetwork", saved.getBoolean("metered"), false);
        field(params, "interfaceNames", strings(saved.getJSONArray("interfaces")), false);
        Parcel request = Parcel.obtain(), reply = Parcel.obtain();
        try {
            request.writeInterfaceToken(DESCRIPTOR);
            request.writeInt(1);
            ((Parcelable) params).writeToParcel(request, 0);
            if (!resolver.transact(TRANSACTION_SET_CONFIGURATION, request, reply, 0)) throw new IllegalStateException("setResolverConfiguration unsupported");
            reply.readException();
        } finally { request.recycle(); reply.recycle(); }
    }

    private void persist() throws Exception {
        FileOutputStream out = journal.startWrite();
        try {
            out.write(leases.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            journal.finishWrite(out);
        } catch (Exception e) { journal.failWrite(out); throw e; }
    }

    private void restore() throws Exception {
        JSONArray remaining = new JSONArray();
        Exception failure = null;
        for (int i = 0; i < leases.length(); i++) {
            JSONObject saved = leases.getJSONObject(i);
            try {
                JSONObject current = info(saved.getInt("netId"));
                // ConnectivityService may already have replaced DNS on a changed network.
                // Restore only a configuration still owned by this lease.
                String[] managed = saved.has("managedServers") ? strings(saved.getJSONArray("managedServers"))
                        : new String[]{AppConfig.DNS_VPN}; // Recover a lease from the preceding personal test build.
                if (Arrays.equals(strings(current.getJSONArray("servers")), managed)
                        && current.getJSONArray("tlsServers").length() == 0) {
                    configure(saved, strings(saved.getJSONArray("servers")));
                }
            } catch (Exception e) {
                // ServiceSpecificException is hidden from the public SDK. ENOENT/ENONET
                // means ConnectivityService already destroyed this network's resolver cache.
                int code = -1;
                if (e.getClass().getName().equals("android.os.ServiceSpecificException")) {
                    code = e.getClass().getField("errorCode").getInt(e);
                }
                if (code != 2 && code != 64) { remaining.put(saved); failure = e; }
            }
        }
        leases = remaining;
        persist();
        if (failure != null) throw failure;
    }

    private void apply(JSONObject network) throws Exception {
        restore();
        JSONObject saved = info(network.getInt("netId"));
        if (saved.getJSONArray("tlsServers").length() != 0 || !network.getBoolean("privateDnsOff")) {
            throw new IllegalStateException("Managed root DNS requires Private DNS off");
        }
        if (saved.getJSONArray("servers").length() == 0) throw new IllegalStateException("Network DNS unavailable");
        saved.put("transports", network.getJSONArray("transports"));
        saved.put("metered", network.getBoolean("metered"));
        saved.put("interfaces", network.getJSONArray("interfaces"));
        saved.put("managedServers", network.getJSONArray("managedServers"));
        String[] managed = strings(saved.getJSONArray("managedServers"));
        if (managed.length != 1) throw new IllegalArgumentException("Expected one managed DNS listener address");
        leases.put(saved);
        persist(); // Write before changing netd, so every partial setup has a recovery record.
        configure(saved, managed);
        if (!Arrays.equals(strings(info(network.getInt("netId")).getJSONArray("servers")), managed)) {
            throw new IllegalStateException("Managed DNS readback failed");
        }
    }

    public static void main(String[] args) {
        if (android.os.Build.VERSION.SDK_INT < 29) {
            System.out.println("V2NG:ERROR:UnsupportedAndroidVersion");
            return;
        }
        RootDnsHelper helper = null;
        try {
            helper = new RootDnsHelper(new File(args[0]));
            helper.restore();
            System.out.println("V2NG:READY");
            BufferedReader commands = new BufferedReader(new InputStreamReader(System.in));
            String line;
            while ((line = commands.readLine()) != null) {
                JSONObject command = new JSONObject(line);
                String operation = command.getString("operation");
                if (operation.equals("apply")) helper.apply(command);
                else if (operation.equals("restore")) helper.restore();
                else if (operation.equals("close")) break;
                else throw new IllegalArgumentException("Unknown DNS operation");
                System.out.println("V2NG:OK");
            }
        } catch (Exception e) {
            System.out.println("V2NG:ERROR:" + e.getClass().getSimpleName());
            System.err.println("Root DNS operation failed: " + e);
        } finally {
            if (helper != null) {
                try { helper.restore(); }
                catch (Exception e) { System.err.println("Root DNS restore failed: " + e); }
            }
            // A daemon crash closes stdin too. This is a lifetime guard, not a polling rule writer.
            try {
                if (args.length == 2) {
                    Process cleanup = new ProcessBuilder("timeout", "-s", "TERM", "-k", "2", "25", "sh", args[1])
                            .redirectErrorStream(true).redirectOutput(new File("/dev/null")).start();
                    cleanup.waitFor();
                }
            } catch (Exception e) { System.err.println("Root route cleanup failed: " + e); }
        }
    }
}
