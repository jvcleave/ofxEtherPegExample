/*
 *  ofxEtherPEG.h
 *  ofxEtherPegExample
 *
 *  Created by Jason Van Cleave on 2/24/12.
 *
 */

#include "ofMain.h"
#include "pcap.h" // see www.tcpdump.com for more information


typedef struct {
	// no ethernet header; please remove it first.
	// IP Header:
	UInt8	versionAndIHL;
	UInt8		typeOfService;
	UInt16			totalLength;
	UInt32	ip1;
	UInt8	timeToLive;
	UInt8		protocol;
	UInt16			headerChecksum;
	UInt32	sourceIP;
	UInt32	destIP;
	// TCP header:
	UInt16	sourcePort;
	UInt16	destPort;
	UInt32	sequenceNumber;
	UInt32	ackNumber;
	UInt8	dataOffsetAndJunk;	// dataOffset is high 4 bits; dataOffset is number of UInt32s in TCP header
#define kFINBit 0x01
	UInt8	moreFlagsAndJunk;
	// etc.
	// whatever
} Packet; 

enum { kFree, kCaptured, kDisplaying};
typedef struct StashedPacket StashedPacket;
struct StashedPacket
{
	SInt32 state;				// Free, captured packet, or data being displayed
	Packet *data;
	SInt32 payloadoffset;
	SInt32 SOI;
	SInt32 EOI;
	StashedPacket *parent;
	StashedPacket *next;
	StashedPacket *following;
};

enum {
	kMaxPacketLength = 1500
};
enum {
	kStashSize = 1000
};


struct Blob {
	int x;
	int y;
	int radius;
	ofColor color;
};
#define BLOB_SIZE 10

class ofxEtherPEG
{
public:
	
	ofxEtherPEG();
	void setup();
	void update();
	void draw();
	void createBlob(int aNumber);
	void termPromiscuity(void);
	vector<Blob>blobs;
};

