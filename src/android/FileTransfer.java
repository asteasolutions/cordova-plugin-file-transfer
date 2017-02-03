/*
       Licensed to the Apache Software Foundation (ASF) under one
       or more contributor license agreements.  See the NOTICE file
       distributed with this work for additional information
       regarding copyright ownership.  The ASF licenses this file
       to you under the Apache License, Version 2.0 (the
       "License"); you may not use this file except in compliance
       with the License.  You may obtain a copy of the License at

         http://www.apache.org/licenses/LICENSE-2.0

       Unless required by applicable law or agreed to in writing,
       software distributed under the License is distributed on an
       "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
       KIND, either express or implied.  See the License for the
       specific language governing permissions and limitations
       under the License.
*/
package org.apache.cordova.filetransfer;

import android.net.Uri;
import android.util.Log;
import android.webkit.CookieManager;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaResourceApi;
import org.apache.cordova.CordovaResourceApi.OpenForReadResult;
import org.apache.cordova.PluginManager;
import org.apache.cordova.PluginResult;
import org.apache.cordova.Whitelist;
import org.apache.cordova.file.FileUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URLConnection;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class FileTransfer extends CordovaPlugin {

    private static final String LOG_TAG = "FileTransfer";

    public static int FILE_NOT_FOUND_ERR = 1;
    public static int INVALID_URL_ERR = 2;
    public static int CONNECTION_ERR = 3;
    public static int PAUSED_ERR = 4;
    public static int NOT_MODIFIED_ERR = 5;

    private static HashMap<String, RequestContext> activeRequests = new HashMap<String, RequestContext>();
    private static final int MAX_BUFFER_SIZE = 5 * 1024 * 1024;

    private static final class RequestContext {
        String source;
        String target;
        File targetFile;
        CallbackContext callbackContext;
        HttpURLConnection connection;
        RequestContext(String source, String target, CallbackContext callbackContext) {
            this.source = source;
            this.target = target;
            this.callbackContext = callbackContext;
        }
        void sendPluginResult(PluginResult pluginResult) {
            synchronized (this) {
                callbackContext.sendPluginResult(pluginResult);
            }
        }
    }

    /**
     * Adds an interface method to an InputStream to return the number of bytes
     * read from the raw stream. This is used to track total progress against
     * the HTTP Content-Length header value from the server.
     */
    private static abstract class TrackingInputStream extends FilterInputStream {
        public TrackingInputStream(final InputStream in) {
            super(in);
        }
        public abstract long getTotalRawBytesRead();
    }

    private static class ExposedGZIPInputStream extends GZIPInputStream {
        public ExposedGZIPInputStream(final InputStream in) throws IOException {
            super(in);
        }
        public Inflater getInflater() {
            return inf;
        }
    }

    /**
     * Provides raw bytes-read tracking for a GZIP input stream. Reports the
     * total number of compressed bytes read from the input, rather than the
     * number of uncompressed bytes.
     */
    private static class TrackingGZIPInputStream extends TrackingInputStream {
        private ExposedGZIPInputStream gzin;
        public TrackingGZIPInputStream(final ExposedGZIPInputStream gzin) throws IOException {
            super(gzin);
            this.gzin = gzin;
        }
        public long getTotalRawBytesRead() {
            return gzin.getInflater().getBytesRead();
        }
    }

    /**
     * Provides simple total-bytes-read tracking for an existing InputStream
     */
    private static class SimpleTrackingInputStream extends TrackingInputStream {
        private long bytesRead = 0;
        public SimpleTrackingInputStream(InputStream stream) {
            super(stream);
        }

        private int updateBytesRead(int newBytesRead) {
            if (newBytesRead != -1) {
                bytesRead += newBytesRead;
            }
            return newBytesRead;
        }

        @Override
        public int read() throws IOException {
            return updateBytesRead(super.read());
        }

        // Note: FilterInputStream delegates read(byte[] bytes) to the below method,
        // so we don't override it or else double count (CB-5631).
        @Override
        public int read(byte[] bytes, int offset, int count) throws IOException {
            return updateBytesRead(super.read(bytes, offset, count));
        }

        public long getTotalRawBytesRead() {
            return bytesRead;
        }
    }

    @Override
    public boolean execute(String action, JSONArray args, final CallbackContext callbackContext) throws JSONException {
        if (action.equals("download")) {
            String source = args.getString(0);
            String target = args.getString(1);
            download(source, target, args, callbackContext);
            return true;
        } else if (action.equals("pause")) {
            String objectId = args.getString(0);
            pause(objectId, callbackContext);
            return true;
        }
        return false;
    }

    private static void addHeadersToRequest(URLConnection connection, JSONObject headers) {
        try {
            for (Iterator<?> iter = headers.keys(); iter.hasNext(); ) {
                /* RFC 2616 says that non-ASCII characters and control
                 * characters are not allowed in header names or values.
                 * Additionally, spaces are not allowed in header names.
                 * RFC 2046 Quoted-printable encoding may be used to encode
                 * arbitrary characters, but we donon- not do that encoding here.
                 */
                String headerKey = iter.next().toString();
                String cleanHeaderKey = headerKey.replaceAll("\\n","")
                        .replaceAll("\\s+","")
                        .replaceAll(":", "")
                        .replaceAll("[^\\x20-\\x7E]+", "");

                JSONArray headerValues = headers.optJSONArray(headerKey);
                if (headerValues == null) {
                    headerValues = new JSONArray();

                     /* RFC 2616 also says that any amount of consecutive linear
                      * whitespace within a header value can be replaced with a
                      * single space character, without affecting the meaning of
                      * that value.
                      */

                    String headerValue = headers.getString(headerKey);
                    String finalValue = headerValue.replaceAll("\\s+", " ").replaceAll("\\n"," ").replaceAll("[^\\x20-\\x7E]+", " ");
                    headerValues.put(finalValue);
                }

                //Use the clean header key, not the one that we passed in
                connection.setRequestProperty(cleanHeaderKey, headerValues.getString(0));
                for (int i = 1; i < headerValues.length(); ++i) {
                    connection.addRequestProperty(headerKey, headerValues.getString(i));
                }
            }
        } catch (JSONException e1) {
            // No headers to be manipulated!
        }
    }

    private String getCookies(final String target) {
        boolean gotCookie = false;
        String cookie = null;
        Class webViewClass = webView.getClass();
        try {
            Method gcmMethod = webViewClass.getMethod("getCookieManager");
            Class iccmClass  = gcmMethod.getReturnType();
            Method gcMethod  = iccmClass.getMethod("getCookie", String.class);

            cookie = (String)gcMethod.invoke(
                    iccmClass.cast(
                            gcmMethod.invoke(webView)
                    ), target);

            gotCookie = true;
        } catch (NoSuchMethodException e) {
        } catch (IllegalAccessException e) {
        } catch (InvocationTargetException e) {
        } catch (ClassCastException e) {
        }

        if (!gotCookie && CookieManager.getInstance() != null) {
            cookie = CookieManager.getInstance().getCookie(target);
        }

        return cookie;
    }

    private static void safeClose(Closeable stream) {
        if (stream != null) {
            try {
                stream.close();
            } catch (IOException e) {
            }
        }
    }

    private static TrackingInputStream getInputStream(URLConnection conn) throws IOException {
        String encoding = conn.getContentEncoding();
        if (encoding != null && encoding.equalsIgnoreCase("gzip")) {
            return new TrackingGZIPInputStream(new ExposedGZIPInputStream(conn.getInputStream()));
        }
        return new SimpleTrackingInputStream(conn.getInputStream());
    }

    // always verify the host - don't check for certificate
    private static final HostnameVerifier DO_NOT_VERIFY = new HostnameVerifier() {
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };
    // Create a trust manager that does not validate certificate chains
    private static final TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[] {};
        }

        public void checkClientTrusted(X509Certificate[] chain,
                                       String authType) throws CertificateException {
        }

        public void checkServerTrusted(X509Certificate[] chain,
                                       String authType) throws CertificateException {
        }
    } };

    /**
     * This function will install a trust manager that will blindly trust all SSL
     * certificates.  The reason this code is being added is to enable developers
     * to do development using self signed SSL certificates on their web server.
     *
     * The standard HttpsURLConnection class will throw an exception on self
     * signed certificates if this code is not run.
     */
    private static SSLSocketFactory trustAllHosts(HttpsURLConnection connection) {
        // Install the all-trusting trust manager
        SSLSocketFactory oldFactory = connection.getSSLSocketFactory();
        try {
            // Install our all trusting manager
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory newFactory = sc.getSocketFactory();
            connection.setSSLSocketFactory(newFactory);
        } catch (Exception e) {
            Log.e(LOG_TAG, e.getMessage(), e);
        }
        return oldFactory;
    }

    private static JSONObject createFileTransferError(int errorCode, String source, String target, URLConnection connection, Throwable throwable) {
        int httpStatus = 0;
        StringBuilder bodyBuilder = new StringBuilder();
        String body = null;
        if (connection != null) {
            try {
                if (connection instanceof HttpURLConnection) {
                    httpStatus = ((HttpURLConnection)connection).getResponseCode();
                    InputStream err = ((HttpURLConnection) connection).getErrorStream();
                    if(err != null)
                    {
                        BufferedReader reader = new BufferedReader(new InputStreamReader(err, "UTF-8"));
                        try {
                            String line = reader.readLine();
                            while(line != null) {
                                bodyBuilder.append(line);
                                line = reader.readLine();
                                if(line != null) {
                                    bodyBuilder.append('\n');
                                }
                            }
                            body = bodyBuilder.toString();
                        } finally {
                            reader.close();
                        }
                    }
                }
                // IOException can leave connection object in a bad state, so catch all exceptions.
            } catch (Throwable e) {
                Log.w(LOG_TAG, "Error getting HTTP status code from connection.", e);
            }
        }

        return createFileTransferError(errorCode, source, target, body, httpStatus, throwable);
    }

    /**
     * Create an error object based on the passed in errorCode
     * @param errorCode      the error
     * @return JSONObject containing the error
     */
    private static JSONObject createFileTransferError(int errorCode, String source, String target, String body, Integer httpStatus, Throwable throwable) {
        JSONObject error = null;
        try {
            error = new JSONObject();
            error.put("code", errorCode);
            error.put("source", source);
            error.put("target", target);
            if(body != null)
            {
                error.put("body", body);
            }
            if (httpStatus != null) {
                error.put("http_status", httpStatus);
            }
            if (throwable != null) {
                String msg = throwable.getMessage();
                if (msg == null || "".equals(msg)) {
                    msg = throwable.toString();
                }
                error.put("exception", msg);
            }
        } catch (JSONException e) {
            Log.e(LOG_TAG, e.getMessage(), e);
        }
        return error;
    }

    /**
     * Downloads a file form a given URL and saves it to the specified directory.
     *
     * @param source        URL of the server to receive the file
     * @param target        Full path of the file on the file system
     */
    private void download(final String source, final String target, JSONArray args, CallbackContext callbackContext) throws JSONException {
        Log.d(LOG_TAG, "download " + source + " to " +  target);

        final CordovaResourceApi resourceApi = webView.getResourceApi();

        final boolean trustEveryone = args.optBoolean(2);
        final String objectId = args.getString(3);
        final JSONObject headers = args.optJSONObject(4);

        final Uri sourceUri = resourceApi.remapUri(Uri.parse(source));
        // Accept a path or a URI for the source.
        Uri tmpTarget = Uri.parse(target);
        final Uri targetUri = resourceApi.remapUri(
                tmpTarget.getScheme() != null ? tmpTarget : Uri.fromFile(new File(target)));

        int uriType = CordovaResourceApi.getUriType(sourceUri);
        final boolean useHttps = uriType == CordovaResourceApi.URI_TYPE_HTTPS;
        final boolean isLocalTransfer = !useHttps && uriType != CordovaResourceApi.URI_TYPE_HTTP;
        if (uriType == CordovaResourceApi.URI_TYPE_UNKNOWN) {
            JSONObject error = createFileTransferError(INVALID_URL_ERR, source, target, null, 0, null);
            Log.e(LOG_TAG, "Unsupported URI: " + sourceUri);
            callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.IO_EXCEPTION, error));
            return;
        }

        /* This code exists for compatibility between 3.x and 4.x versions of Cordova.
         * Previously the CordovaWebView class had a method, getWhitelist, which would
         * return a Whitelist object. Since the fixed whitelist is removed in Cordova 4.x,
         * the correct call now is to shouldAllowRequest from the plugin manager.
         */
        Boolean shouldAllowRequest = null;
        if (isLocalTransfer) {
            shouldAllowRequest = true;
        }
        if (shouldAllowRequest == null) {
            try {
                Method gwl = webView.getClass().getMethod("getWhitelist");
                Whitelist whitelist = (Whitelist)gwl.invoke(webView);
                shouldAllowRequest = whitelist.isUrlWhiteListed(source);
            } catch (NoSuchMethodException e) {
            } catch (IllegalAccessException e) {
            } catch (InvocationTargetException e) {
            }
        }
        if (shouldAllowRequest == null) {
            try {
                Method gpm = webView.getClass().getMethod("getPluginManager");
                PluginManager pm = (PluginManager)gpm.invoke(webView);
                Method san = pm.getClass().getMethod("shouldAllowRequest", String.class);
                shouldAllowRequest = (Boolean)san.invoke(pm, source);
            } catch (NoSuchMethodException e) {
            } catch (IllegalAccessException e) {
            } catch (InvocationTargetException e) {
            }
        }

        if (!Boolean.TRUE.equals(shouldAllowRequest)) {
            Log.w(LOG_TAG, "Source URL is not in white list: '" + source + "'");
            JSONObject error = createFileTransferError(CONNECTION_ERR, source, target, null, 401, null);
            callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.IO_EXCEPTION, error));
            return;
        }


        final RequestContext context = new RequestContext(source, target, callbackContext);
        synchronized (activeRequests) {
            activeRequests.put(objectId, context);
        }

        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                HttpURLConnection connection = null;
                HostnameVerifier oldHostnameVerifier = null;
                SSLSocketFactory oldSocketFactory = null;
                File file = null;
                PluginResult result = null;
                TrackingInputStream inputStream = null;
                boolean cached = false;

                OutputStream outputStream = null;
                try {
                    OpenForReadResult readResult = null;

                    file = resourceApi.mapUriToFile(targetUri);
                    context.targetFile = file;

                    Log.d(LOG_TAG, "Download file:" + sourceUri);
                    long fileSize = file.length();

                    FileProgressResult progress = new FileProgressResult();

                    if (isLocalTransfer) {
                        readResult = resourceApi.openForRead(sourceUri);
                        if (readResult.length != -1) {
                            progress.setLengthComputable(true);
                            progress.setTotal(readResult.length);
                        }
                        inputStream = new SimpleTrackingInputStream(readResult.inputStream);
                    } else {
                        // connect to server
                        // Open a HTTP connection to the URL based on protocol
                        connection = resourceApi.createHttpConnection(sourceUri);
                        if (useHttps && trustEveryone) {
                            // Setup the HTTPS connection class to trust everyone
                            HttpsURLConnection https = (HttpsURLConnection)connection;
                            oldSocketFactory = trustAllHosts(https);
                            // Save the current hostnameVerifier
                            oldHostnameVerifier = https.getHostnameVerifier();
                            // Setup the connection not to verify hostnames
                            https.setHostnameVerifier(DO_NOT_VERIFY);
                        }

                        connection.setRequestMethod("GET");

                        // TODO: Make OkHttp use this CookieManager by default.
                        String cookie = getCookies(sourceUri.toString());

                        if(cookie != null)
                        {
                            connection.setRequestProperty("cookie", cookie);
                        }

                        // This must be explicitly set for gzip progress tracking to work.
                        connection.setRequestProperty("Accept-Encoding", "gzip");

                        // Handle the other headers
                        if (headers != null) {
                            addHeadersToRequest(connection, headers);
                        }

                        if (fileSize != 0) {
                            connection.setRequestProperty("Range", "bytes=" + fileSize + "-");
                        }

                        connection.connect();
                        if (connection.getResponseCode() == HttpURLConnection.HTTP_NOT_MODIFIED) {
                            cached = true;
                            connection.disconnect();
                            Log.d(LOG_TAG, "Resource not modified: " + source);
                            JSONObject error = createFileTransferError(NOT_MODIFIED_ERR, source, target, connection, null);
                            result = new PluginResult(PluginResult.Status.ERROR, error);
                        } else {
                            if (connection.getContentEncoding() == null || connection.getContentEncoding().equalsIgnoreCase("gzip")) {
                                // Only trust content-length header if we understand
                                // the encoding -- identity or gzip
                                if (connection.getContentLength() != -1) {
                                    progress.setLengthComputable(true);
                                    progress.setTotal(fileSize + connection.getContentLength());
                                }
                            }
                            inputStream = getInputStream(connection);
                        }
                    }

                    if (!cached) {
                        try {
                            synchronized (context) {
                                context.connection = connection;
                            }

                            // write bytes to file
                            byte[] buffer = new byte[MAX_BUFFER_SIZE];
                            int bytesRead = 0;
                            outputStream = resourceApi.openOutputStream(targetUri, true);
                            while ((bytesRead = inputStream.read(buffer)) > 0) {
                                outputStream.write(buffer, 0, bytesRead);
                                // Send a progress event.
                                progress.setLoaded(fileSize + inputStream.getTotalRawBytesRead());
                                PluginResult progressResult = new PluginResult(PluginResult.Status.OK, progress.toJSONObject());
                                progressResult.setKeepCallback(true);
                                context.sendPluginResult(progressResult);
                            }
                        } finally {
                            synchronized (context) {
                                context.connection = null;
                            }
                            safeClose(inputStream);
                            safeClose(outputStream);
                        }

                        Log.d(LOG_TAG, "Saved file: " + target);


                        // create FileEntry object
                        Class webViewClass = webView.getClass();
                        PluginManager pm = null;
                        try {
                            Method gpm = webViewClass.getMethod("getPluginManager");
                            pm = (PluginManager) gpm.invoke(webView);
                        } catch (NoSuchMethodException e) {
                        } catch (IllegalAccessException e) {
                        } catch (InvocationTargetException e) {
                        }
                        if (pm == null) {
                            try {
                                Field pmf = webViewClass.getField("pluginManager");
                                pm = (PluginManager)pmf.get(webView);
                            } catch (NoSuchFieldException e) {
                            } catch (IllegalAccessException e) {
                            }
                        }
                        file = resourceApi.mapUriToFile(targetUri);
                        context.targetFile = file;
                        FileUtils filePlugin = (FileUtils) pm.getPlugin("File");
                        if (filePlugin != null) {
                            JSONObject fileEntry = filePlugin.getEntryForFile(file);
                            if (fileEntry != null) {
                                result = new PluginResult(PluginResult.Status.OK, fileEntry);
                            } else {
                                JSONObject error = createFileTransferError(CONNECTION_ERR, source, target, connection, null);
                                Log.e(LOG_TAG, "File plugin cannot represent download path");
                                result = new PluginResult(PluginResult.Status.IO_EXCEPTION, error);
                            }
                        } else {
                            Log.e(LOG_TAG, "File plugin not found; cannot save downloaded file");
                            result = new PluginResult(PluginResult.Status.ERROR, "File plugin not found; cannot save downloaded file");
                        }
                    }
                } catch (FileNotFoundException e) {
                    JSONObject error = createFileTransferError(FILE_NOT_FOUND_ERR, source, target, connection, e);
                    Log.e(LOG_TAG, error.toString(), e);
                    result = new PluginResult(PluginResult.Status.IO_EXCEPTION, error);
                } catch (IOException e) {
                    JSONObject error = createFileTransferError(CONNECTION_ERR, source, target, connection, e);
                    Log.e(LOG_TAG, error.toString(), e);
                    result = new PluginResult(PluginResult.Status.IO_EXCEPTION, error);
                } catch (JSONException e) {
                    Log.e(LOG_TAG, e.getMessage(), e);
                    result = new PluginResult(PluginResult.Status.JSON_EXCEPTION);
                } catch (Throwable e) {
                    JSONObject error = createFileTransferError(CONNECTION_ERR, source, target, connection, e);
                    Log.e(LOG_TAG, error.toString(), e);
                    result = new PluginResult(PluginResult.Status.IO_EXCEPTION, error);
                } finally {
                    synchronized (activeRequests) {
                        activeRequests.remove(objectId);
                    }

                    if (connection != null) {
                        // Revert back to the proper verifier and socket factories
                        if (trustEveryone && useHttps) {
                            HttpsURLConnection https = (HttpsURLConnection) connection;
                            https.setHostnameVerifier(oldHostnameVerifier);
                            https.setSSLSocketFactory(oldSocketFactory);
                        }
                    }

                    if (result == null) {
                        result = new PluginResult(PluginResult.Status.ERROR, createFileTransferError(CONNECTION_ERR, source, target, connection, null));
                    }

                    context.sendPluginResult(result);
                }
            }
        });
    }

    /**
     * Pause an ongoing upload or download.
     */
    private void pause(String objectId, final CallbackContext callback) {
        final RequestContext context;
        synchronized (activeRequests) {
            context = activeRequests.remove(objectId);
        }
        if (context != null) {
            // Closing the streams can block, so execute on a background thread.
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    synchronized (context) {
                        // Trigger the pause callback immediately to minimize latency between it and pause() being called.
                        JSONObject error = createFileTransferError(PAUSED_ERR, context.source, context.target, null, -1, null);
                        context.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, error));
                        if (context.connection != null) {
                            try {
                                context.connection.disconnect();
                            } catch (Exception e) {
                                Log.e(LOG_TAG, "CB-8431 Catch workaround for fatal exception", e);
                            } finally {
                                callback.success();
                            }
                        }
                    }
                }
            });
        }
    }
}
