package de.qabel.core.accounting;

import de.qabel.core.config.SyncSettingItem;

import java.util.ArrayList;

public class AccountingProfile extends SyncSettingItem {

	private int quota;
	private ArrayList<String> prefixes;

	public AccountingProfile() {
	}

	public AccountingProfile(int quota, String prefix) {
		this.quota = quota;
		this.prefixes = new ArrayList();
		this.prefixes.add(prefix);
	}

	public AccountingProfile(int quota, ArrayList<String> prefixes) {
		this.quota = quota;
		this.prefixes = prefixes;
	}

	public int getQuota() {
		return quota;
	}

	public void setQuota(int quota) {
		this.quota = quota;
	}

	public ArrayList<String> getPrefixes() {
		return prefixes;
	}

	public void setPrefixes(ArrayList<String> prefixes) {
		this.prefixes = prefixes;
	}

	public void addPrefix(String prefix) {
		this.prefixes.add(prefix);
	}
}
