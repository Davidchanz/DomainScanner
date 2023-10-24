package org.domenscaner;

import inet.ipaddr.AddressComponent;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressSeqRange;
import inet.ipaddr.IPAddressString;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.client.ClientProtocolException;
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
import sun.net.util.IPAddressUtil;
import sun.security.x509.IPAddressName;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

public class DomenScaner {
    public static final String PEER_CERTIFICATES = "PEER_CERTIFICATES";
    public static void scan(String ipRange, int threadNum, String filename) {//51.38.24.0/24
        IPAddressSeqRange startIPAddress = new IPAddressString(ipRange).getSequentialRange();
        List<IPAddress> addresses = new ArrayList<>();
        startIPAddress.iterator().forEachRemaining(addresses::add);

        FileWriter fw;
        try {
            fw = new FileWriter(filename + ".txt");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        BufferedWriter bw = new BufferedWriter(fw);

        List<List<IPAddress>> addressesGroups = splitArrayList(addresses, addresses.size()/threadNum);
        List<Thread> threads = new ArrayList<>();

        for(List<IPAddress> groupAddresses: addressesGroups){
            threads.add(new Thread(() -> {
                groupAddresses.forEach(ipAddress -> {
                    try {
                        scanIpAddress(ipAddress.toString(), bw);
                    } catch (IOException e) {
                        //throw new RuntimeException(e);
                    } catch (CertificateParsingException e) {
                        //throw new RuntimeException(e);
                    }
                });
            }));
            threads.get(threads.size()-1).start();
        }
        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        try {
            bw.close();
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static <T> List<List<T>> splitArrayList(List<T> source, int chunkSize) {
        List<List<T>> destination = new ArrayList<>();

        for (int i = 0; i < source.size(); i += chunkSize) {
            int end = Math.min(i + chunkSize, source.size());
            destination.add(source.subList(i, end));
        }

        return destination;
    }

    private static void scanIpAddress(String ipAddress, BufferedWriter bw) throws IOException, CertificateParsingException {
        CloseableHttpClient httpClient = null;
        try {
            // create http response certificate interceptor
            HttpResponseInterceptor certificateInterceptor = (httpResponse, context) -> {
                ManagedHttpClientConnection routedConnection = (ManagedHttpClientConnection)context.getAttribute(HttpCoreContext.HTTP_CONNECTION);
                SSLSession sslSession = routedConnection.getSSLSession();
                if (sslSession != null) {

                    // get the server certificates from the {@Link SSLSession}
                    Certificate[] certificates = sslSession.getPeerCertificates();

                    // add the certificates to the context, where we can later grab it from
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

            // create closable http client and assign the certificate interceptor
            httpClient = HttpClients
                    .custom()
                    .setConnectionManager(connectionManager)
                    .addInterceptorLast(certificateInterceptor)
                    .build();

            // make HTTP GET request to resource server
            HttpGet httpget = new HttpGet("https://" + ipAddress);
            System.out.println("Executing request " + httpget.getRequestLine());

            // create http context where the certificate will be added
            HttpContext context = new BasicHttpContext();
            httpClient.execute(httpget, context);

            // obtain the server certificates from the context
            Certificate[] peerCertificates = (Certificate[])context.getAttribute(PEER_CERTIFICATES);

            // loop over certificates and print meta-data
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
                                    } catch (IOException e) {
                                        throw new RuntimeException(e);
                                    }
                            });
                    });
            }

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        } finally {
            // close httpclient
            try {
                httpClient.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }


}
