/*
 *  ofxEtherPEG.h
 *  ofxEtherPegExample
 *
 *  Created by Jason Van Cleave on 2/24/12.
 *
 */

#include "ofMain.h"
#include "pcap.h" // see www.tcpdump.com for more information

#include "Promiscuity.h"
extern "C" {
	#include "SortFrames.h"

};
struct Blob {
	int size;
	ofColor color;
};

class ofxEtherPEG
{
public:
	
	ofxEtherPEG();
	void setup();
	void update();
	void draw();
	void showBlob(int aNumber);
	vector<Blob>blobs;
};