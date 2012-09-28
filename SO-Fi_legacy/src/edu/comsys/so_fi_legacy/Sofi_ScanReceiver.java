/**
 *  This program is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free Software
 *  Foundation; either version 3 of the License, or (at your option) any later
 *  version.
 *  You should have received a copy of the GNU General Public License along with
 *  this program; if not, see <http://www.gnu.org/licenses/>.
 *  Use this application at your own risk.
 *
 *  Copyright (c) 2012 by Benjamin Grap.
 */


package edu.comsys.so_fi_legacy;


import java.util.List;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.util.Log;
import android.widget.Toast;

public class Sofi_ScanReceiver extends BroadcastReceiver{
	private static final String TAG = "Pwifi_ScanReceiver";
	
	MainActivity pwifiActivity;
	
	public Sofi_ScanReceiver(MainActivity pwifiActivity) {
		  super();
		  this.pwifiActivity = pwifiActivity;
	}
	
	@Override
	public void onReceive(Context context, Intent intent) {
		//pwifiActivity.printState("Scan received!");
		if(pwifiActivity.Scanning){
			List<ScanResult> results = pwifiActivity.wifi.getScanResults();
			for (ScanResult result : results) {
				if(result.SSID.contains("#;")){
					ssid recvdssid = new ssid(result.SSID);
					//pwifiActivity.printState(String.format("So-Fi Network found: %s ID: %s MyId: %s", result.SSID, recvdssid.getID(), pwifiActivity.ComId));
					if(recvdssid.getID() == pwifiActivity.ComId){
						/* Received an Answer */
						if(pwifiActivity.Connected == false && pwifiActivity.SolutionSend == false && pwifiActivity.PuzzleReceived == false){
							pwifiActivity.puzzleReceived(recvdssid);
							//String message = String.format("Network found: \"%s\"", result.SSID);
							//pwifiActivity.printState(message);
						}
					}
				}
			}
		}
	}
	

}
