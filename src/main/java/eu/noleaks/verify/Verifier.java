/*
 * Copyright (c) 2012, Axeos B.V, and contributors
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Axeos designates this
 * particular file as subject to the "Classpath" exception as provided
 * in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package eu.noleaks.verify;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.logging.Level;
import java.util.logging.Logger;

final class Verifier {

    private final List<String> crlFileNames = new ArrayList<>();
    private final Set<String> displayedWarnings = new HashSet<>();
    private final Logger logger = Logger.getLogger(Verifier.class.getName());
    private PKIXParameters params;
    private CertPathValidator validator;
    private Date verificationDate;

    void setVerificationDate(Date verificationDate) {
        this.verificationDate = verificationDate;
    }

    void setLevel(Level level) {
        logger.setLevel(level);
    }

    void verifyJar(final JarFile jarFile) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, CRLException, VerifierException {
        displayedWarnings.clear();
        final byte[] buffer = new byte[8192];
        boolean anySigned = false;
        boolean hasUnsignedEntry = false;
        initPathValidator();
        final Manifest manifest = jarFile.getManifest();

        Enumeration<JarEntry> entriesEnum = jarFile.entries();
        while (entriesEnum.hasMoreElements()) {
            JarEntry entry = entriesEnum.nextElement();

            logger.log(Level.INFO, "Checking file " + entry);
            try (InputStream is = jarFile.getInputStream(entry)) {
                // Checking SHA-1
                while ((is.read(buffer, 0, buffer.length)) != -1) {
                }
            } catch (SecurityException e) {
                logger.log(Level.SEVERE, "Invalid signature", e);
                throw new InvalidException();
            }

            String name = entry.getName();
            CodeSigner[] codeSigners = entry.getCodeSigners();

            boolean isSigned = (codeSigners != null);
            boolean inManifest = ((manifest.getAttributes(name) != null) || (manifest.getAttributes("./" + name) != null) || (manifest.getAttributes("/" + name) != null));
            anySigned |= isSigned;
            hasUnsignedEntry |= !entry.isDirectory() && !isSigned && !isSignatureRelatedFilename(name);

            logger.log(Level.INFO, (isSigned ? "signed" : " ") + " " + (inManifest ? "manifest" : " "));

            if (isSigned) {
                for (CodeSigner codeSigner : codeSigners) {
                    Certificate cert = codeSigner.getSignerCertPath().getCertificates().get(0);
                    Timestamp timestamp = codeSigner.getTimestamp();
                    if (timestamp != null) {
                        logger.log(Level.INFO, "Found timestamp.");
                        CertPath cp = timestamp.getSignerCertPath();
                        try {
                            logger.log(Level.INFO, "Validating timestamp certificate path");
                            validatePath(cp);
                            params.setDate(timestamp.getTimestamp());
                        } catch (Exception e) {
                            logger.log(Level.SEVERE, "Timestamp certificate is not valid.", e);
                        }
                    }

                    final List<Certificate> x = new ArrayList<>(codeSigner.getSignerCertPath().getCertificates());
                    CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(x);

                    if (cert instanceof X509Certificate) {
                        logger.log(Level.INFO, "Found certificate SerialNumber: " + ((X509Certificate) cert).getSerialNumber() + "; Subject: " + ((X509Certificate) cert).getSubjectDN());
                        if (!isCertForCodeSigning((X509Certificate) cert)) {
                            logger.log(Level.INFO, "This file contains entries whose signer certificate's ExtendedKeyUsage extension doesn't allow code signing.");
                        }
                    }

                    try {
                        logger.log(Level.INFO, "Validating signer certificate path");
                        validatePath(path);
                    } catch (VerifierException e) {
                        throw e;
                    } catch (Exception e) {
                        if ("Path does not chain with any of the trust anchors".equals(e.getMessage())) {
                            throw new NotTrustedException();
                        }

                        if (e instanceof CertificateExpiredException) {
                            throw new ExpiredException();
                        } else if (e.getCause() instanceof CertificateExpiredException) {
                            throw new ExpiredException();
                        }

                        logger.log(Level.SEVERE, "Certificate path can't be verified", e);
                        throw new NotTrustedException();
                    }
                }
            }
        }

        if (!anySigned) {
            logger.log(Level.SEVERE, "File is not signed");
            throw new NotSignedException();
        } else if (hasUnsignedEntry) {
            logger.log(Level.SEVERE, "File contains unsigned entries");
            throw new UnsignedEntriesException();
        }
        logger.log(Level.INFO, "File verified.");
    }

    private void initPathValidator() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException, InvalidAlgorithmParameterException, CRLException, VerifierException {
        System.setProperty("com.sun.net.ssl.checkRevocation", "true");
        System.setProperty("com.sun.security.enableCRLDP", "true");
        Security.setProperty("ocsp.enable", "true");

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        KeyStore keystore = loadKeystore();
        try {
            this.params = new PKIXParameters(keystore);
        } catch (InvalidAlgorithmParameterException e) {
            throw new NotTrustedException();
        }

        if (verificationDate != null) {
            logger.log(Level.INFO, "Using verification date: " + verificationDate);
            this.params.setDate(verificationDate);
        }

        final List<CRL> crls = new ArrayList<>();
        params.setRevocationEnabled(!crlFileNames.isEmpty());
        for (String crlFile : crlFileNames) {
            crls.addAll(CertificateFactory.getInstance("X.509").generateCRLs(new FileInputStream(crlFile)));
        }

        final CollectionCertStoreParameters csParams = new CollectionCertStoreParameters(crls);
        CertStore certStore = CertStore.getInstance("Collection", csParams);
        params.addCertStore(certStore);
        this.validator = validator;
    }

    private boolean isCertForCodeSigning(final X509Certificate cert) throws CertificateParsingException {
        List<String> extUsage = cert.getExtendedKeyUsage();
        // 2.5.29.37.0 - Any extended key usage
        // 1.3.6.1.5.5.7.3.3 - Code Signing
        return extUsage != null && (extUsage.contains("2.5.29.37.0") || extUsage.contains("1.3.6.1.5.5.7.3.3"));
    }

    private boolean isSignatureRelatedFilename(String filename) {
        String tmp = filename.toUpperCase();
        if (tmp.equals(JarFile.MANIFEST_NAME) || tmp.equals("META-INF/") || (tmp.startsWith("META-INF/SIG-") && tmp.indexOf("/") == tmp.lastIndexOf("/"))) {
            return true;
        }
        if (tmp.startsWith("META-INF/") && (tmp.endsWith(".SF") || tmp.endsWith(".DSA") || tmp.endsWith(".RSA"))) {
            return (tmp.indexOf("/") == tmp.lastIndexOf("/"));
        }

        return false;
    }

    private KeyStore loadKeystore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        final File trustStore = new File(System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar));
        final File userStore = new File("~/.keystore");

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        if (userStore.exists()) {
            logger.log(Level.INFO, "Using keystore: " + userStore);
            keystore.load(new FileInputStream(userStore), null);
        } else if (trustStore.exists()) {
            logger.log(Level.INFO, "Using keystore: " + trustStore);
            keystore.load(new FileInputStream(trustStore), null);
        } else {
            keystore.load(null);
        }

        return keystore;
    }

    private void validatePath(CertPath path) throws Exception {
        if (validator == null) {
            logger.log(Level.SEVERE, "Validation of the certificate path requires keystore.");
            return;
        }

        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(path, params);
        if (result == null)
            logger.log(Level.SEVERE, "No result returned");
        try {
            if (params.getDate() == null) {
                result.getTrustAnchor().getTrustedCert().checkValidity();
            } else {
                result.getTrustAnchor().getTrustedCert().checkValidity(params.getDate());
            }
        } catch (Exception e) {
            throw new ExpiredException();
        }

        logger.log(Level.INFO, "Certificate path valid.");
    }
}
