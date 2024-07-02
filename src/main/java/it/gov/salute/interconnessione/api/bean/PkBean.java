/* SPDX-License-Identifier: BSD-3-Clause */

package it.gov.salute.interconnessione.api.bean;

import java.io.Serializable;
import java.security.PublicKey;

public class PkBean implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 8247137254430149430L;
	private PublicKey pub = null;

	public PublicKey getPub() {
		return pub;
	}

	public void setPub(PublicKey pub) {
		this.pub = pub;
	}

}
