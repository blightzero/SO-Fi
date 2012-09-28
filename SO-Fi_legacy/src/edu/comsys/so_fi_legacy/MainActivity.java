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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Random;
import android.net.wifi.ScanResult;
import android.net.wifi.SupplicantState;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiManager.WifiLock;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.IntentFilter;
import android.content.pm.ActivityInfo;
import android.content.res.Configuration;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

public class MainActivity extends Activity implements OnClickListener,AdapterView.OnItemSelectedListener{
    /** Called when the activity is first created. */
	private static final String TAG = "Sofi_legacy";
	private TextView stateText;
	private Button scanButton;
	private EditText ssidEdit;
	private Spinner typeSpinner;
	private WifiInfo currentNetwork;
	private CheckBox quickCheck;
	private int currentRequestType = 2;
	private Handler mHandler = new Handler();
	private Handler uHandler = new Handler();
	private String postString = "";
	
	//Public Variables (Used in Pwifi_ScanReceiver)
	public WifiManager wifi;
	public int pwifiNetworkId;
	public String scanTarget;
	public String scanString = "00000000000000000000";
	public String psk;
	public byte [][] hashList;
	public BroadcastReceiver receiver;
	public BroadcastReceiver Suppreceiver;
	public Sofi_hashConversion encoder;
	public ssid ssidEncoder;
	public ssid SSID;
	public Random Randgen = new Random();
	public Rfc2898DeriveBytes pskCompute;
	public boolean Scanning = false;
	public boolean PuzzleReceived = false;
	public boolean SolutionSend = false;
	public boolean Connected = false;
	public int ComId = 0;
	public byte[] Puzzle;
	public int PuzzleBitSize;
	public WifiLock wifiLock;
	public long startTime;
	public long endTime;
	public long startBuildScanTime;
	public long endBuildScanTime;
	public long startScanDiscoverTime;
	public long endScanDiscoverTime;
	public long startBuildConnectTime;
	public long endBuildConnectTime;
	public long startConnectDiscoverTime;
	public long endConnectDiscoverTime;
	public long startPuzzleTime;
	public long endPuzzleTime;
	
	/**
	 * Cofiguration Variables
	 */
	public boolean isEval = true;
	public int PBKDF2Rounds = 256; // 256 or 4096
	
	//Constants
	// Private Constants
	private final static String [] requestTypes = {"Connection","Group","File","Person"};
		
	// Public Constants
	/* Character representation for a legacy client. */
	public final static char PWIFI_CS_LEGACY = '0';
	/* Character representation for a native client. */
	public final static char PWIFI_CS_NATIVE = '1';
	/* Character representation for a simple connection request. */
	public final static char PWIFI_CS_CONNECTION = '0';
	/* Character representation for a group network request. */
	public final static char PWIFI_CS_GROUP = '1';
	/* Character representation for a file request. */
	public final static char PWIFI_CS_FILE = '2';
	/* Character representation for a people search request. */
	public final static char PWIFI_CS_PEOPLE = '3';
	/* Version */
	public final static char PWIFI_VERSION = '1';
	/* Search Timeout */
	public final static int TIMEOUT = 20000;
	
	
	/**
	 * Begin Code
	 */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        //GetEncoder Instance
        encoder = new Sofi_hashConversion();
        ssidEncoder = new ssid();
        //Get UI References
        stateText = (TextView) findViewById(R.id.wifi_state_text);
        scanButton = (Button) findViewById(R.id.scanButton);
        ssidEdit = (EditText) findViewById(R.id.ssidEdit);
        typeSpinner = (Spinner) findViewById(R.id.spinner1);
        quickCheck = (CheckBox) findViewById(R.id.checkBox1);
        //Register OnClickListener in this Activity.
        scanButton.setOnClickListener(this);
        
        //Set scanTarget to all Zero
        scanTarget = "00000000000000000000";
        
        //Get WifiManager Reference
        wifi = (WifiManager)getSystemService(WIFI_SERVICE);
        wifiLock = wifi.createWifiLock(wifi.WIFI_MODE_FULL_HIGH_PERF, "So-Fi Lock");
        //Register Broadcast Receivers
     	//1. for Wifi Scan Results
        if (receiver == null){
     		receiver = new Sofi_ScanReceiver(this);
     	}
   		registerReceiver(receiver, new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));
   		
   		//2. for Supplicant State Changes such as Successful Connections.
   		if (Suppreceiver == null){
     		Suppreceiver = new Sofi_SupplicantStateReceiver(this);
     	}
   		registerReceiver(Suppreceiver, new IntentFilter(WifiManager.SUPPLICANT_STATE_CHANGED_ACTION));
   		
        
   		//Change stateText Text. Write Something, so we know we are ready to go.
        stateText.setText("WiFi registered and ready to go!\n");
        ArrayAdapter<String> spinnerAdapter = new ArrayAdapter(this,android.R.layout.simple_spinner_item,requestTypes);
        typeSpinner.setAdapter(spinnerAdapter);
        typeSpinner.setOnItemSelectedListener(this);
        typeSpinner.setSelection(2);
    }
    
    public void onItemSelected(AdapterView<?> parent, View v, int position,long id) {
    	currentRequestType = position;
	}

	public void onNothingSelected(AdapterView<?> parent) {
		currentRequestType = 2;
	}
    
	@Override
	public void onClick(View v) {
			
		if (v.getId() == R.id.scanButton) {
			if(quickCheck.isChecked()){
				PBKDF2Rounds = 256;
			}else{
				PBKDF2Rounds = 4096;
			}
			if(wifi.isWifiEnabled()){
		    	currentNetwork = wifi.getConnectionInfo();
		    }else{
		    	wifi.setWifiEnabled(true);
		    	while(!wifi.isWifiEnabled()){
		    		android.os.SystemClock.sleep(100);
		    	}
		    }
			Thread ScanThread = new Thread(RunScans);
			ScanThread.start();
			if(this.isEval){
				scanString = encoder.sanitize(ssidEdit.getText().toString());
				Thread thread = new Thread(RunConnect);
				thread.start();
			}else{
				scanString = encoder.sanitize(ssidEdit.getText().toString());
				scan(scanString);
			}
		}
		
	}
	
	/**
	 * 
	 * @param target
	 */
	private void scan(String target){
		if(Scanning==false){
			Connected=false;
			PuzzleReceived = false;
			SolutionSend = false;
			
			startBuildScanTime = android.os.SystemClock.elapsedRealtime();
		    removeOldNetworks();
		    
		    this.ComId = Randgen.nextInt(255);
			WifiConfiguration pwifiNetwork = new WifiConfiguration();
			
			hashList = encoder.trippleHash(scanString);
			ssidEncoder = new ssid(hashList[2],false,false,true,false,2,this.ComId,0);
		    scanTarget = ssidEncoder.toString();

			pwifiNetwork.SSID = "\"" + scanTarget + "\"";
		    pwifiNetwork.hiddenSSID = true;
		    pwifiNetwork.preSharedKey = psk;
		    pwifiNetwork.priority = 255;
		    pwifiNetwork.status = WifiConfiguration.Status.CURRENT;
		    wifiLock.acquire();
		    wifi.disconnect();
		    pwifiNetworkId = wifi.addNetwork(pwifiNetwork);
		    
		    if(pwifiNetworkId != -1){
		    	wifi.enableNetwork(pwifiNetworkId,true);
		    	Scanning = true;
		    	printState("Scanning for SSID: \"" + scanTarget + "\" with ID: " + pwifiNetworkId + ".");
				mHandler.removeCallbacks(mTimeOutScan);
				mHandler.postDelayed(mTimeOutScan, TIMEOUT);
				wifi.reconnect();
				endBuildScanTime = android.os.SystemClock.elapsedRealtime();
				startScanDiscoverTime = android.os.SystemClock.elapsedRealtime();
			}else{
				printState("Could not create Network Entry for a Scan.");
			}
		}else{
			printState("Already searching for another Item. Please wait for Timeout!");
		}
	}
	
	/**
	 * 
	 * @param ssidEncoder
	 */
	private void connect(ssid ssidEncoder){
		Connected=false;
		printState("Connecting...");
		startBuildConnectTime = android.os.SystemClock.elapsedRealtime();

	    removeOldNetworks();
		WifiConfiguration pwifiNetwork = new WifiConfiguration();
	    scanTarget = ssidEncoder.toString();
	    
	    try {
	    	pskCompute = new Rfc2898DeriveBytes(hashList[0],scanTarget.getBytes(),PBKDF2Rounds);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    psk = ByteArrayToString(pskCompute.getBytes(32));
	    
		pwifiNetwork.SSID = "\"" + scanTarget + "\"";
	    pwifiNetwork.hiddenSSID = true;
	    pwifiNetwork.preSharedKey = psk; 
	    pwifiNetwork.priority = 255;
	    pwifiNetwork.status = WifiConfiguration.Status.CURRENT;
	    wifiLock.acquire();
	    wifi.disconnect();
	    pwifiNetworkId = wifi.addNetwork(pwifiNetwork);
	    
	    if(pwifiNetworkId != -1){
	    	wifi.enableNetwork(pwifiNetworkId,true);
			PuzzleReceived = true;
			SolutionSend = true;
	    	printState("Connecting to SSID: \"" + scanTarget + "\" with ID: " + pwifiNetworkId + ".");
			printState("Using PSK: \"" + psk + "\"");
			mHandler.removeCallbacks(mTimeOutScan);
			mHandler.postDelayed(mTimeOutScan, TIMEOUT);
			wifi.reconnect();
			endBuildConnectTime = android.os.SystemClock.elapsedRealtime();
			startConnectDiscoverTime = android.os.SystemClock.elapsedRealtime();
		}else{
			printState("Could not create Network Entry to connect.");
		}
	}
	
	private Runnable mTimeOutScan = new Runnable(){
		public void run(){
			WifiInfo result = wifi.getConnectionInfo();
			SupplicantState supState = result.getSupplicantState();
			if(supState == SupplicantState.COMPLETED){
				if(result.getSSID() != null){
					if(!result.getSSID().equals(scanTarget) ){
						wifi.disconnect();
						removeOldNetworks();
						printState("Nothing was found in " + TIMEOUT/1000 + " seconds!");
						wifi.disconnect();
					    Scanning = false;
					}
				}else{
					wifi.disconnect();
					removeOldNetworks();
					printState("Nothing was found in " + TIMEOUT/1000 + " seconds!");
					wifi.disconnect();
					Scanning = false;
				}
			}else{
				wifi.disconnect();
				removeOldNetworks();
				printState("Nothing was found in " + TIMEOUT/1000 + " seconds!");
				wifi.disconnect();
				Scanning = false;
			}
		}
	};
	
	public void puzzleReceived(ssid recvdSSID){
		printState("Solving Puzzle...");
		endScanDiscoverTime = android.os.SystemClock.elapsedRealtime();
		PuzzleReceived = true;
		Puzzle = encoder.xorBytes(hashList[1], recvdSSID.getHash());
		PuzzleBitSize = recvdSSID.getBitSize();
		printState("Received Puzzle! BitSize: " + PuzzleBitSize + "Puzzle: " + ByteArrayToString(Puzzle));
		SSID = recvdSSID;
		Thread thread = new Thread(SolvePuzzleConnect);
		thread.start();
	}
	
	private Runnable SolvePuzzleConnect = new Runnable(){
		public void run(){
			startPuzzleTime = android.os.SystemClock.elapsedRealtime();
			byte [] solution;
			byte [] ssidHash;
			puzzle myPuzzle = new puzzle(Puzzle,PuzzleBitSize);
			solution = myPuzzle.getSolution();
			ssidHash = encoder.xorBytes(hashList[1], solution);
			endPuzzleTime = android.os.SystemClock.elapsedRealtime();
			connect(new ssid(ssidHash, false, false, true, true, 2, ComId, PuzzleBitSize));
		}
	};
	
	private Runnable RunConnect = new Runnable(){
		public void run(){
			int sampleSize = 110;
			String csvList = ssidEdit.getText().toString() + ",";
			String csvBScanList = "Build Scan,";
			String csvScanDList = "Scan Discovery,";
			String csvPuzzleList =  "Solve Puzzle,";
			String csvConnectBList = "Build Connect (WPA),";
			String csvConnectDList = "Connect,";
			
			for (int i=0;i<sampleSize;i++){
				wifi.removeNetwork(pwifiNetworkId);
				android.os.SystemClock.sleep(2000);
				startTime = android.os.SystemClock.elapsedRealtime();
				scan(ssidEdit.getText().toString());
				while(true){
					android.os.SystemClock.sleep(500);
					if(Connected){
						break;
					}
					if(!Scanning){
						printState("Connect failed after timeout!");
						endTime = android.os.SystemClock.elapsedRealtime();
						endScanDiscoverTime = endTime;
						endPuzzleTime = startPuzzleTime;
						endBuildConnectTime = startBuildConnectTime;
						endConnectDiscoverTime = startConnectDiscoverTime;
						break;
					}
				}
				printState(String.format("Build Scan: %s ms", endBuildScanTime - startBuildScanTime));
				printState(String.format("Scan Discover: %s ms", endScanDiscoverTime - startScanDiscoverTime));
				printState(String.format("Solve Puzzle: %s ms", endPuzzleTime - startPuzzleTime));
				printState(String.format("Build Connect (WPA): %s ms", endBuildConnectTime - startBuildConnectTime));
				printState(String.format("Connect Discover: %s ms", endConnectDiscoverTime - startConnectDiscoverTime));

				printState(String.format("In try %s connecting took: %s ms",i,(endTime - startTime)));
				csvList += String.format("%s,",(endTime - startTime));
				csvBScanList += String.format("%s,",(endBuildScanTime - startBuildScanTime));
				csvScanDList += String.format("%s,",(endScanDiscoverTime - startScanDiscoverTime));
				csvPuzzleList += String.format("%s,",(endPuzzleTime - startPuzzleTime));
				csvConnectBList += String.format("%s,",(endBuildConnectTime - startBuildConnectTime));
				csvConnectDList += String.format("%s,",(endConnectDiscoverTime - startConnectDiscoverTime));
			}
			csvList += "\n";
			csvBScanList += "\n";
			csvScanDList += "\n";
			csvPuzzleList += "\n";
			csvConnectBList += "\n";
			csvConnectDList += "\n";
			
			String FILENAME = "Android_Client_"+ android.os.Build.MODEL + "_to_" + "SO-Fi_Puzzle_WPA_";/*scanTarget; */
			FILENAME = FILENAME + PBKDF2Rounds;
			FILENAME = FILENAME + "_connect.csv";
			File file = new File(Environment.getExternalStorageDirectory(), FILENAME);
			FileWriter fos;
			try {
			    fos = new FileWriter(file,true);
			    fos.append(csvList);
			    fos.append(csvBScanList);
				fos.append(csvScanDList); 
				fos.append(csvPuzzleList);
				fos.append(csvConnectBList);
				fos.append(csvConnectDList);
			    fos.flush();
			    fos.close();
			} catch (FileNotFoundException e) {
			    // handle exception
			} catch (IOException e) {
			    // handle exception
			}
			printState("Done!");
		}
	};
	
	private Runnable RunScans = new Runnable(){
		public void run(){
			while(true){
				android.os.SystemClock.sleep(1000);
				wifi.startScan();
				uHandler.post(mUpdateResults);
			}
		}
	};
	
	
	/**
	 * 
	 * @param ba
	 * @return
	 */
    public static String ByteArrayToString(byte[] ba)
    {
    	StringBuilder sb = new StringBuilder();
        for (byte b : ba) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
    
    final Runnable mUpdateResults = new Runnable() {
        public void run() {
            updateResultsInUi();
        }
    };
    
    private void updateResultsInUi(){
    	if(!postString.equals("")){
	    	stateText.setText(postString + "\n" + stateText.getText());
	    	postString = "";
    	}
    }
    
    
	public void printState(String s){
		postString = postString + "\n" + s;
	}
	
    
	@Override
	public void onDestroy(){
		wifi.disconnect();
		mHandler.removeCallbacks(mTimeOutScan);
		removeOldNetworks();
		super.onDestroy();
		if(wifiLock.isHeld()){
			wifiLock.release();
		}
        unregisterReceiver(receiver);
        unregisterReceiver(Suppreceiver);
	}
	
	@Override
	public void onConfigurationChanged(Configuration newConfig) {
	    super.onConfigurationChanged(newConfig);
	    setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_PORTRAIT);
	}
	
	private void removeOldNetworks(){
		//Identify and delete all the old networks that we created.
		boolean changed = true;
		List<WifiConfiguration> config;
		
		while(changed){
			changed = false;
			config = wifi.getConfiguredNetworks();
			for (WifiConfiguration conf : config){
				if(conf.SSID.contains("#;")){
					wifi.removeNetwork(conf.networkId);
					changed = true;
				}
			}
		}
	}
	
    
}
