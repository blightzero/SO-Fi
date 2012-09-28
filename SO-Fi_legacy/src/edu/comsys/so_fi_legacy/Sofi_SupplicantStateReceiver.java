/**
 *  This program is free software; you can redistribute it and/or modify it under
 *  the terms of the GNU General Public License as published by the Free Software
 *  Foundation; either version 3 of the License, or (at your option) any later
 *  version.
 *  You should have received a copy of the GNU General Public License along with
 *  this program; if not, see <http://www.gnu.org/licenses/>.
 *  Use this application at your own risk.
 *
 *  Copyright (c) 2012 Benjamin Grap.
 */


package edu.comsys.so_fi_legacy;

import java.util.List;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.DhcpInfo;
import android.net.Uri;
import android.net.wifi.ScanResult;
import android.net.wifi.SupplicantState;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.widget.Toast;

public class Sofi_SupplicantStateReceiver extends BroadcastReceiver{
	private static final String TAG = "Pwifi_SipplicantStateReceiver";
	
	MainActivity pwifiActivity;
	
	public Sofi_SupplicantStateReceiver(MainActivity pwifiActivity) {
		  super();
		  this.pwifiActivity = pwifiActivity;
	}
	
	@Override
	public void onReceive(Context context, Intent intent) {
		DhcpInfo dhcp;
		WifiInfo result = pwifiActivity.wifi.getConnectionInfo();
		String MacAddress = result.getMacAddress().replace(":", "");
		SupplicantState supState = result.getSupplicantState();
		int dhcpIp=0;
		String url = new String();
		if(pwifiActivity.Connected==false){
			if(supState == SupplicantState.COMPLETED){
				if(result.getSSID() != null){
					String message = String.format("Connected to network: %s.", result.getSSID());
					pwifiActivity.printState(message);
					
					//Depending on the Network we should now do something here.
					//If this actually is a Pwifi Network we should connect back to the DHCP Server and get the IE via the Legacy UDP.
					if(result.getSSID().equals(pwifiActivity.scanTarget) ){ //&& dhcpIp != 0){
						//Do a simple HTTP Download from the DHCP Server Address.
						pwifiActivity.Scanning = false;
						pwifiActivity.PuzzleReceived = true;
						pwifiActivity.SolutionSend = true;
						pwifiActivity.Connected = true;
						
						pwifiActivity.printState("So-Fi Network Connected!");
						pwifiActivity.endTime = android.os.SystemClock.elapsedRealtime();
						pwifiActivity.endConnectDiscoverTime = android.os.SystemClock.elapsedRealtime();
						/**
						 * If we are in Evaluation Mode we do not need to wait for DHCP, or open a Browser
						 */
						if(pwifiActivity.isEval){
							//nothing.
						}else{
							while(!intToIp(dhcpIp).contains("10.0.")){
								android.os.SystemClock.sleep(200);
								dhcp = pwifiActivity.wifi.getDhcpInfo();
								dhcpIp = dhcp.serverAddress;
							}
							//url = "http://" + intToIp(dhcpIp) + ":8010/index?address="+ MacAddress+ "&request=" + pwifiActivity.ByteArrayToString(pwifiActivity.hashList[0]);  
							url = "http://" + "10.0.0.1" + ":8010/index?address="+ MacAddress+ "&request=" + pwifiActivity.ByteArrayToString(pwifiActivity.hashList[0]);
							pwifiActivity.printState("Found DHCP IP: " + intToIp(dhcpIp));
							context.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
						}
					}
				}
			}
		}
	}
	
	private static String intToIp(int i) {
		return ( i & 0xFF) + "." + ((i >> 8 ) & 0xFF) + "." +  ((i >> 16 ) & 0xFF) + "." + ((i >> 24 ) & 0xFF);
		//return ((i >> 24 ) & 0xFF) + "." +	((i >> 16 ) & 0xFF) + "." +	((i >> 8 ) & 0xFF) + "." +	( i & 0xFF);
	}

	private static int ipToInt(String addr) {
		String[] addrArray = addr.split("\\.");
		int num = 0;
		int power = 0;
		
		for (int i=0;i<addrArray.length;i++) {
			power = 3-i;
			num += ((Integer.parseInt(addrArray[i])%256 * Math.pow(256,power)));
		}
		return num;
	}
}

