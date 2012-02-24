/*
 *  ofxEtherPEG.cpp
 *  ofxEtherPegExample
 *
 *  Created by Jason Van Cleave on 2/24/12.
 *  Copyright 2012 __MyCompanyName__. All rights reserved.
 *
 */

#include "ofxEtherPEG.h"

static pcap_t *pcap_session = NULL;

#define INTERFACE	"en1"

ofxEtherPEG::ofxEtherPEG()
{

}
void ofxEtherPEG::setup()
{
	char errorBuffer[PCAP_ERRBUF_SIZE];
	char *device = INTERFACE; // should find all ethernet interfaces and open each
tryAgain:
	pcap_session = pcap_open_live( device, BUFSIZ, 1, 1, errorBuffer );
	if( NULL == pcap_session ) {
		AlertStdAlertParamRec alertParams = {
			true,							// movable, sure
			false,							// no help button
			NULL,							// no event filter
			"\pTry Again",					// OK
			"\pQuit",						// Cancel
			NULL,							// no other button
			kAlertStdAlertOKButton,			// which is OK
			kAlertStdAlertCancelButton,		// which is Cancel
			kWindowAlertPositionMainScreen	// where to appear
		};
		SInt16 itemHit;
		fprintf( stderr, "EtherPEG: pcap_open_live failed: %s\n", errorBuffer );
		StandardAlert( 
					  kAlertStopAlert,
					  "\pCould not connect to ethernet device \"" INTERFACE "\".",
					  "\pUse \"sudo chmod 777 /dev/bpf*\" to enable promiscuous access to ethernet devices.  "
					  "Use \"ifconfig -a\" to check the device name.  "
					  "You may need to rebuild EtherPEG with the right device name.  Sucky, eh?",
					  &alertParams,
					  &itemHit );
		if( kAlertStdAlertOKButton == itemHit ) goto tryAgain;
		ExitToShell();
	}
}

void ofxEtherPEG::update()
{
	const unsigned char *ethernetPacket;
	const Packet *p;
	struct pcap_pkthdr header;
	
	ethernetPacket = pcap_next( pcap_session, &header );
	if( ethernetPacket ) {
		if( *(unsigned short *)(ethernetPacket+12) == EndianU16_NtoB(0x0800) ) { // ETHERTYPE_IP
			// skip ethernet header: 6 byte source, 6 byte dest, 2 byte type
			p = (Packet *)( ethernetPacket + 6 + 6 + 2 );
		}
		else if( *(unsigned short *)(ethernetPacket+12) == EndianU16_NtoB(0x8864) ) { // ETHERTYPE_???
			// skip ethernet header: 6 byte source, 6 byte dest, 2 byte type,
			// plus 8 bytes I don't know much about, but often seemed to be
			// 11 00 07 fb 05 b0 00 21.  something about promiscuous mode?
			p = (Packet *)( ethernetPacket + 6 + 6 + 2 + 8 );
		}
		else {
			// some other kind of packet -- no concern of ours
			return;
		}
#if 1
		if (p->protocol != 6)
			printf("p->protocol != 6\n");
		else if ((p->versionAndIHL & 0x0F) != 5)
			printf("(p->versionAndIHL & 0x0F) != 5\n");
		else if ((p->totalLength < 40) && !(p->moreFlagsAndJunk & kFINBit))
			printf("(p->totalLength < 40) && !(p->moreFlagsAndJunk & kFINBit)\n");
#endif
		if ((p->protocol == 6) && ((p->versionAndIHL & 0x0F) == 5)) {
			if ((p->totalLength > 40) || (p->moreFlagsAndJunk & kFINBit)) {
				showBlob(ConsumePacket( p ));
			}
			else showBlob( 0 ); // yellow
		}
		else showBlob( 0 ); // yellow
	}
}
void ofxEtherPEG::showBlob(int aNumber)
{
	ofColor color;
	switch (aNumber) 
	{
		case 0:
		{
			color = ofColor::yellow;
			break;
		}
		case 1:
		{
			color = ofColor::black;
			break;
		}
		case 2:
		{
			color = ofColor::green;
			break;
		}
		default:
		{
			color = ofColor::blue;
			break;
		}
	}
	Blob blob;
	blob.size = 4;
	blob.color = color;
	
	blobs.push_back(blob);
	
	
}
void ofxEtherPEG::draw()
{
	ofPushStyle();
	if (blobs.size()>0) 
	{
		int contentWidth = ( (4*blobs.size()) + (blobs.size()*2) );
		int numRows = contentWidth/ofGetWidth();
		
		
		cout << "numRows: " << numRows << endl;
		cout << "contentWidth: " << contentWidth << endl;
		
		
	}
	
	/*for (int i=0; i<blobs.size(); i++) 
	{
		//ofSetRectMode(OF_RECTMODE_CORNER);
		ofSetColor(blobs[i].color);

		if (xCounter>ofGetWidth()) 
		{
			//cout << i << ": xCounter : " << xCounter << endl;
			xCounter = 0;
			rowCounter++;
			ofRect(xCounter, blobs[i].size*rowCounter, blobs[i].size, blobs[i].size);
		}else {
			xCounter+=(blobs[i].size*i) + (i*2);
		}
		cout << i << ": xCounter : " << xCounter << endl;

	}*/
	
	ofPopStyle();
}
