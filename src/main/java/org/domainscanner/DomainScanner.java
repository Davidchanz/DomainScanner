package org.domainscanner;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressString;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ManagedHttpClientConnection;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

public class DomainScanner {
    public static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";
    public static List<String> scan(String ipRange, int threadNum, String filename) throws IOException, InterruptedException {
        FileWriter fw;
        fw = new FileWriter(filename);
        BufferedWriter bw = new BufferedWriter(fw);

        IPAddressSeqRange startIPAddress = new IPAddressString(ipRange).getSequentialRange();
        List<IPAddress> addresses = new ArrayList<>();
        startIPAddress.iterator().forEachRemaining(addresses::add);
        List<String> result = Collections.synchronizedList(new ArrayList<>());
        List<List<IPAddress>> addressesGroups = splitArrayList(addresses, Math.max(addresses.size()/threadNum, 1));
        List<Thread> threads = new ArrayList<>();

        for(List<IPAddress> groupAddresses: addressesGroups){
            threads.add(new Thread(() -> {
                for(IPAddress ipAddress: groupAddresses){
                    try {
                        scanIpAddress(ipAddress.toString(), bw, result);
                    } catch (Exception e) {
                        System.err.println("Exception handled while scan IP: " + ipAddress.toString());
                    }
                }
            }));
            threads.get(threads.size()-1).start();
        }
        for (Thread thread : threads) {
            thread.join();
        }
        bw.close();
        fw.close();

        return result;
    }

    public static <T> List<List<T>> splitArrayList(List<T> source, int chunkSize) {
        List<List<T>> destination = new ArrayList<>();

        for (int i = 0; i < source.size(); i += chunkSize) {
            int end = Math.min(i + chunkSize, source.size());
            destination.add(source.subList(i, end));
        }

        return destination;
    }

    private static void scanIpAddress(String ipAddress, BufferedWriter bw, List<String> result) throws IOException, CertificateParsingException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        CloseableHttpClient httpClient = null;
        try {
            HttpResponseInterceptor certificateInterceptor = (httpResponse, context) -> {
                ManagedHttpClientConnection routedConnection = (ManagedHttpClientConnection)context.getAttribute(HttpCoreContext.HTTP_CONNECTION);
                SSLSession sslSession = routedConnection.getSSLSession();
                if (sslSession != null) {
                    Certificate[] certificates = sslSession.getPeerCertificates();
                    context.setAttribute(PEER_CERTIFICATES, certificates);
                }
            };

            final TrustStrategy acceptingTrustStrategy = (cert, authType) -> true;
            final SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(null, acceptingTrustStrategy)
                    .build();
            final SSLConnectionSocketFactory sslsf =
                    new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
            final Registry<ConnectionSocketFactory> socketFactoryRegistry =
                    RegistryBuilder.<ConnectionSocketFactory> create()
                            .register("https", sslsf)
                            .register("http", new PlainConnectionSocketFactory())
                            .build();

            final BasicHttpClientConnectionManager connectionManager =
                    new BasicHttpClientConnectionManager(socketFactoryRegistry);

            httpClient = HttpClients
                    .custom()
                    .setConnectionManager(connectionManager)
                    .addInterceptorLast(certificateInterceptor)
                    .build();

            HttpGet httpget = new HttpGet("https://" + ipAddress);
            System.out.println("Executing request " + httpget.getRequestLine());

            HttpContext context = new BasicHttpContext();
            httpClient.execute(httpget, context);

            Certificate[] peerCertificates = (Certificate[])context.getAttribute(PEER_CERTIFICATES);

            for (Certificate certificate : peerCertificates){
                X509Certificate real = (X509Certificate) certificate;
                if(real.getSubjectAlternativeNames() != null)
                    real.getSubjectAlternativeNames().forEach(objects -> {
                        if(objects != null)
                            objects.forEach(name -> {
                                if(name instanceof String)
                                    try {
                                        bw.write("IP: " + ipAddress + ", Domain: " + name.toString() + "\n");
                                        bw.flush();
                                        result.add("IP: " + ipAddress + ", Domain: " + name.toString());
                                    } catch (IOException e) {
                                        System.err.println("Exception handled while write Domain for IP: " + ipAddress.toString());
                                    }
                            });
                    });
            }
        } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            throw e;
        } finally {
            assert httpClient != null;
            httpClient.close();
        }
    }

}
