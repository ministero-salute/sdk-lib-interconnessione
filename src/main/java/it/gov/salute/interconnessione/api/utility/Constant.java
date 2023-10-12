package it.gov.salute.interconnessione.api.utility;

import it.gov.salute.interconnessione.api.exception.InterconnessioneApiException;

public interface Constant {
	
	// configurazione per cifratore RSA (modalità ECB e padding PKCS#1) padding randomico
	public final static String ALGORITHM = "RSA/ECB/PKCS1Padding"; 
	// configurazione per cifratore RSA (modalità ECB e padding costante)
//	public final static String ALGORITHM = "RSA/ECB/NoPadding"; 

	public final static String BC_PROVIDER = "BC";
	
	public final static String BEGIN = "-----BEGIN RSA PUBLIC KEY-----";
	public final static String END = "-----END RSA PUBLIC KEY-----";
	public final static String TAG_HEX = "0203";
	public final static int HMAC_ANESTESISTA_LENGTH = 64;
	
	public final static InterconnessioneApiException CERTIFICATO_NON_VALIDO = new InterconnessioneApiException("EX-01 - Certificato non valido");
	public final static InterconnessioneApiException FORMATO_CHIAVE_NON_VALIDO = new InterconnessioneApiException("EX-02 - Formato chiave non valido");
	public final static InterconnessioneApiException FORMATO_CHIAVE_NULL = new InterconnessioneApiException("EX-03 - Chiave mancante");
	public final static InterconnessioneApiException FORMATO_CAMPO_NON_VALIDO = new InterconnessioneApiException("EX-04 - Campo codice medico vuoto");
	public final static InterconnessioneApiException IDENTIFICATIVO_PAZIENTE_VUOTO = new InterconnessioneApiException("EX-05 - Identificativo paziente non valorizzato");
	public final static InterconnessioneApiException IDENTIFICATIVO_PAZIENTE_NOREGEX = new InterconnessioneApiException("EX-06 - L'Identificativo paziente non rispetta le regole di validazione");
	public final static InterconnessioneApiException PARAMETRI_NON_VALIDI = new InterconnessioneApiException("EX-07 - Parametri non validi");
	public final static InterconnessioneApiException CAMPO_VUOTO = new InterconnessioneApiException("EX-08 - Campo vuoto");

	
	public final static String CODICE_FISCALE_REGEX = "^[a-zA-Z]{6}[0-9]{2}[abcdehlmprstABCDEHLMPRST]{1}[0-9]{2}([a-zA-Z]{1}[a-zA-Z0-9]{3})[a-zA-Z]{1}$";
	public final static String CODICE_STP_REGEX = "^[sS]{1}[tT]{1}[pP]{1}[0-9]{13}$";
	public final static String CODICE_FISCALE_REGEX_OMOCODIA = "^[A-Za-z]{6}[0-9lmnpqrstuvLMNPQRSTUV]{2}[abcdehlmprstABCDEHLMPRST]{1}[0-9lmnpqrstuvLMNPQRSTUV]{2}[A-Za-z]{1}[0-9lmnpqrstuvLMNPQRSTUV]{3}[A-Za-z]{1}$";
	public final static String CODICE_ENI_REGEX = "^[eE]{1}[nN]{1}[iI]{1}[0-9]{13}$";
	public final static String CODICE_GIUBILEO_REGEX = "^[gG]{1}[iI]{1}[uU]{1}[0-9]{13}$";
	public final static String TEAM_REGEX = "^[ \\.,'-/_a-zA-Z0-9]{1,20}$";
	public final static String CODICE_IDENTIFICATIVO_VUOTO = "^[xX]{16}$|^[xX]{20}$";
	public final static String CODICE_FISCALE_TEMPORANEO_NUMERICO = "\\d{11}";

	public final static String CODICE_FISCALE_CIFRATO_REGEX = "^[a-zA-Z0-9+/]{170}[a-zA-Z0-9+/=]{1}[=]{1}$";
	public final static String CODICE_FISCALE_DECIFRATO_REGEX = "^(0\\s){108}((0|[4][8-9]|[5-9][0-9]|1[0-1][0-9]|12[0-2])\\s){4}(([4][8-9]|[5-9][0-9]|1[0-1][0-9]|12[0-2])\\s){15}([4][8-9]|[5-9][0-9]|1[0-1][0-9]|12[0-2]){1}$";
	
	public static interface Charsets{
		public final static String UTF_8 = "UTF-8";
	}
}
