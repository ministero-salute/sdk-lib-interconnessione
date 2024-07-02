/* SPDX-License-Identifier: BSD-3-Clause */

package it.gov.salute.interconnessione.api.core;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.HmacUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import it.gov.salute.crypto.engine.SMIMECrypto;
import it.gov.salute.crypto.utils.CryptoUtil;
import it.gov.salute.interconnessione.api.bean.PemFile;
import it.gov.salute.interconnessione.api.exception.InterconnessioneApiException;
import it.gov.salute.interconnessione.api.utility.Constant;
import it.gov.salute.interconnessione.api.utility.Constant.Charsets;

public class InterconnessioneApi {
	
	private Cipher								cipherRSAEncrypt	= null;
	private Cipher								cipherRSADecrypt	= null;
	private static InterconnessioneApi			instance			= null;
	private final static byte[]					CHECK_HMAC_KEY		= "e!h[Bvr52b4R<C}wWkE(w.".getBytes();
	// Chiave flusso SDO
	private final static String					SD3_KEY				= "f9774c199764e186f6c3066375845377d20a090a9066f0ca3804a2d57e7c15ad";
	private final boolean						ADD_CHECK			= true;
	
	private static final BouncyCastleProvider	securityProvider;
	
	static {
		
		securityProvider = new BouncyCastleProvider();
		Security.addProvider(securityProvider);
	}
	
	public static Provider getSecurityProvider() {
		
		return securityProvider;
	}
	
	private InterconnessioneApi() {
		
	}
	
	private InterconnessioneApi(File certificato) throws Exception {
		
		try {
			
			if (certificato == null || !certificato.exists()) {
				
				throw Constant.CERTIFICATO_NON_VALIDO;
			}
			
			initEncryptionCipher(certificato);
		}
		catch (Exception e) {
			
			throw e;
		}
	}
	
	private InterconnessioneApi(File certificato,
								File chiavePrivata)
			throws Exception {
		
		try {
			
			if (certificato == null || !certificato.exists()) {
				
				throw Constant.CERTIFICATO_NON_VALIDO;
			}
			
			if (chiavePrivata == null || !chiavePrivata.exists()) {
				
				throw Constant.FORMATO_CHIAVE_NULL;
			}
			
			initEncryptionCipher(certificato);
			initDecryptionCipher(chiavePrivata);
		}
		catch (Exception e) {
			
			throw e;
		}
	}
	
	private void initEncryptionCipher(File certificato) throws Exception {
		
		try {
			
			PemFile pemFile = new PemFile(certificato);
			
			byte[] content = pemFile.getPemObject().getContent();
			
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
			
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			
			PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
			
			this.cipherRSAEncrypt = Cipher.getInstance(	Constant.ALGORITHM,
														securityProvider);
			
			this.cipherRSAEncrypt.init(	Cipher.ENCRYPT_MODE,
										publicKey);
		}
		catch (Exception e) {
			
			throw e;
		}
	}
	
	private void initDecryptionCipher(File chiavePrivata) throws Exception {
		
		try {
			
			PemFile pemFile = new PemFile(chiavePrivata);
			
			byte[] content = pemFile.getPemObject().getContent();
			
			PKCS8EncodedKeySpec pvtKeySpec = new PKCS8EncodedKeySpec(content);
			
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			
			PrivateKey privateKey = keyFactory.generatePrivate(pvtKeySpec);
			
			this.cipherRSADecrypt = Cipher.getInstance(	Constant.ALGORITHM,
														securityProvider);
			
			this.cipherRSADecrypt.init(	Cipher.DECRYPT_MODE,
										privateKey);
		}
		catch (Exception e) {
			
			throw e;
		}
	}
	
	/**
	 * @return Restituisce l'istanza delle API. Da usare se non si dispone di
	 *         certificato ( Flussi non SDO ) ..oppure per utilizzare tutti quei
	 *         metodi che non si appoggiano alle variabili d'istanza
	 * @throws Exception
	 */
	public static InterconnessioneApi getInstance() throws Exception {
		
		try {
			
			if (InterconnessioneApi.instance == null) {
				
				InterconnessioneApi.instance = new InterconnessioneApi();
			}
			
			return InterconnessioneApi.instance;
		}
		catch (Exception e) {
			
			throw e;
		}
	}
	
	/**
	 * @param certificato
	 *            Il certificato necessario alla cifratura
	 *            dell'identificativo paziente, scaricabile tramite Admin
	 *            Console
	 * @return Restituisce l'istanza delle Api
	 * @throws Exception
	 */
	public final static InterconnessioneApi getInstance(File certificato) throws Exception {
		
		try {
			
			if (InterconnessioneApi.instance == null) {
				
				InterconnessioneApi.instance = new InterconnessioneApi(certificato);
			}
			
			return InterconnessioneApi.instance;
		}
		catch (Exception e) {
			
			throw e;
		}
	}
	
	/**
	 * @param certificato
	 *            Il certificato necessario alla cifratura
	 *            dell'identificativo paziente, scaricabile tramite Admin
	 *            Console
	 * @param chiavePrivata
	 *            Chiave privata per permettere la decodifica dei contenuti cifrati
	 * @return Restituisce l'istanza delle Api
	 * @throws Exception
	 */
	public final static InterconnessioneApi getInstance(File certificato,
														File chiavePrivata)
			throws Exception {
		
		try {
			
			if (InterconnessioneApi.instance == null) {
				
				InterconnessioneApi.instance = new InterconnessioneApi(	certificato,
																		chiavePrivata);
			}
			
			return InterconnessioneApi.instance;
		}
		catch (Exception e) {
			
			throw e;
		}
	}
	
	/**
	 * Distrugge l'istanza di InterconnessioneAPI
	 */
	public final static void destroyInstance() {
		
		InterconnessioneApi.instance = null;
	}
	
	/**
	 * @param data
	 *            Valore del campo anestesista da cui generare l'hmac
	 * @param chiave
	 *            La chiave da utilizzare per la codifica. La chiave deve essere
	 *            scaricata dall'Admin Console
	 * @return Restituisce l'hmac del campo in ingresso
	 * @throws Exception
	 */
	public final String hmacSha256(	final String data,
									final String chiave)
			throws Exception {
		
		try {
			if (chiave == null || chiave.trim().equals("")) {
				throw Constant.FORMATO_CHIAVE_NULL;
			}
			else if (chiave != null && chiave.trim().length() != 64) {
				throw Constant.FORMATO_CHIAVE_NON_VALIDO;
			}
			else if (data == null || data.trim().equals("")) {
				throw Constant.FORMATO_CAMPO_NON_VALIDO;
			}
			else {
				byte[] hmac = HmacUtils.hmacSha256(	Hex.decodeHex(chiave.toCharArray()),
													data.getBytes(Charsets.UTF_8));
				
				if (ADD_CHECK) {
					
					if (chiave.equals(SD3_KEY)) {
						byte[] check = HmacUtils.hmacSha256(CHECK_HMAC_KEY,
															hmac);
						return Base64.encodeBase64String(hmac) + Base64.encodeBase64String(check);
					}
					else {
						byte[] check = HmacUtils.hmacSha256(chiave.getBytes("UTF-8"),
															hmac);
						return Base64.encodeBase64String(hmac) + Base64.encodeBase64String(check);
					}
					
				}
				else {
					return Base64.encodeBase64String(hmac);
				}
			}
		}
		catch (Exception e) {
			throw e;
		}
	}
	
	/**
	 * @param data
	 *            Valore del campo codice identificativo paziente da cui
	 *            generare il CUNI
	 * @param chiaveCuni
	 *            La chiave da utilizzare per la codifica. La chiave deve
	 *            essere scaricata dall'Admin Console( chiave CUNI )
	 * @return Restituisce il CUNI del campo in ingresso
	 * @throws Exception
	 */
	public final String cuni(	final String data,
								final String chiaveCuni)
			throws Exception {
		
		try {
			return hmacSha256(	data,
								chiaveCuni);
		}
		catch (Exception e) {
			throw e;
		}
	}
	
	/**
	 * @param data
	 *            Valore del campo identificativo paziente da cifrare
	 * @return Restituisce il campo identificativo paziente cifrato
	 * @throws Exception
	 */
	public final String cifra(final String data) throws Exception {
		
		try {
			
			if (data != null && !data.trim().equals("")) {
				
				if (data.matches(Constant.CODICE_FISCALE_REGEX) || data.matches(Constant.CODICE_STP_REGEX)
						|| data.matches(Constant.CODICE_ENI_REGEX) || data.matches(Constant.CODICE_STP_REGEX)
						|| data.matches(Constant.CODICE_GIUBILEO_REGEX) || data.matches(Constant.TEAM_REGEX)
						|| data.matches(Constant.CODICE_IDENTIFICATIVO_VUOTO)
						|| data.matches(Constant.CODICE_FISCALE_REGEX_OMOCODIA)
						|| data.matches(Constant.CODICE_FISCALE_TEMPORANEO_NUMERICO)) {
					
					byte[] encoded = this.cipherRSAEncrypt.doFinal(data.getBytes(Charsets.UTF_8));
					return Base64.encodeBase64String(encoded);
				}
				else {
					
					throw Constant.IDENTIFICATIVO_PAZIENTE_NOREGEX;
				}
			}
			else {
				
				throw Constant.IDENTIFICATIVO_PAZIENTE_VUOTO;
			}
		}
		catch (Exception e) {
			
			throw e;
		}
	}
	
	/**
	 * @param data
	 *            Valore della stringa da cifrare
	 * @return Restituisce la stringa cifrata
	 * @throws Exception
	 */
	public final String cifraGenerico(final String data) throws Exception {
		
		try {
			
			if (data != null && !data.trim().equals("")) {
				
				byte[] encoded = this.cipherRSAEncrypt.doFinal(data.getBytes(Charsets.UTF_8));
				return Base64.encodeBase64String(encoded);
			}
			else {
				
				throw Constant.CAMPO_VUOTO;
			}
		}
		catch (Exception e) {
			
			throw e;
		}
	}
	
	/**
	 * @param data
	 *            Valore della stringa cifrata
	 * 			
	 * @return Restituisce la stringa decifrata
	 * @throws Exception
	 */
	public final String decifraGenerico(final String data) throws Exception {
		
		try {
			
			if (data != null && !data.trim().equals("")) {
				byte[] decoded = Base64.decodeBase64(data.getBytes(Charsets.UTF_8));
				return new String(this.cipherRSADecrypt.doFinal(decoded));
				
			}
			else {
				
				throw Constant.CAMPO_VUOTO;
			}
		}
		catch (Exception e) {
			
			throw e;
		}
	}
	
	/**
	 * cifra i dati (senza firmarli) con codifica di output base64
	 * 
	 * @param dataToEncryptInputStream
	 *            InputStream aperto sulla risorsa contenente
	 *            i dati da cifrare
	 * @param certificateInputStream
	 *            InputStream aperto sulla risorsa contenente
	 *            i dati del certificato (in formato PEM) da
	 *            utilizzare per la cifratura
	 * @param encryptedDataOutputStream
	 *            OutputStream aperto sulla risorsa sulla
	 *            quale si vuole scrivere il risultato
	 *            dell'operazione di cifratura
	 * @throws Exception
	 */
	public void cifraFile(	InputStream dataToEncryptInputStream,
							InputStream certificateInputStream,
							OutputStream encryptedDataOutputStream)
			throws Exception {
		
		try {
			
			if (dataToEncryptInputStream == null || encryptedDataOutputStream == null) {
				
				throw Constant.PARAMETRI_NON_VALIDI;
			}
			
			X509Certificate encryptionCertificate = null;
			
			if (certificateInputStream != null) {
				
				try {
					
					encryptionCertificate = CryptoUtil.getX509CertificateFromStream(certificateInputStream);
				}
				catch (Exception e) {
					
					throw new InterconnessioneApiException(	Constant.CERTIFICATO_NON_VALIDO.getMessage(),
															e);
				}
			}
			
			if (encryptionCertificate == null) {
				
				throw Constant.CERTIFICATO_NON_VALIDO;
			}
			
			SMIMECrypto.signAndEncryptData(	dataToEncryptInputStream,
											encryptionCertificate,
											null,
											encryptedDataOutputStream,
											true);
		}
		catch (Exception e) {
			
			throw e;
		}
	}
	
	/**
	 * decifra i dati (privi di firma) a partire dal contenuto cifrato e codificato
	 * in base64
	 * 
	 * @param dataToDecryptInputStream
	 *            InputStream aperto sulla risorsa contenente
	 *            i dati da decifrare
	 * @param privateKeyInputStream
	 *            InputStream aperto sulla risorsa contenente
	 *            i dati della chiave privata (in formato PEM)
	 *            da utilizzare per la decifratura
	 * @param decryptedDataOutputStream
	 *            OutputStream aperto sulla risorsa sulla
	 *            quale si vuole scrivere il risultato
	 *            dell'operazione di decifratura
	 * @throws Exception
	 */
	public void decifraFile(InputStream dataToDecryptInputStream,
							InputStream privateKeyInputStream,
							OutputStream decryptedDataOutputStream)
			throws Exception {
		
		try {
			
			if (dataToDecryptInputStream == null || decryptedDataOutputStream == null) {
				
				throw Constant.PARAMETRI_NON_VALIDI;
			}
			
			PrivateKey decryptionKey = null;
			
			if (privateKeyInputStream != null) {
				
				try {
					
					decryptionKey = CryptoUtil.getPrivateKeyFromStream(privateKeyInputStream);
				}
				catch (Exception e) {
					
					throw new InterconnessioneApiException(	Constant.FORMATO_CHIAVE_NON_VALIDO.getMessage(),
															e);
				}
			}
			
			if (decryptionKey == null) {
				
				throw Constant.FORMATO_CHIAVE_NULL;
			}
			
			SMIMECrypto.decryptAndVerifyData(	dataToDecryptInputStream,
												null,
												decryptionKey,
												decryptedDataOutputStream,
												true);
		}
		catch (Exception e) {
			
			throw e;
		}
	}
	
}
