/*
 *  ofxEtherPEG.cpp
 *  ofxEtherPegExample
 *
 *  Created by Jason Van Cleave on 2/24/12.
 *  Copyright 2012 __MyCompanyName__. All rights reserved.
 *
 */

#include "ofxEtherPEG.h"
int kMaxPacketLength = 100500;
static pcap_t *pcap_session = NULL;

#define INTERFACE	"en0"
int xCounter = 0;
int rowCounter = 1;

StashedPacket stash[kStashSize];
UInt32 nextStashEntry = 0;
GraphicsImportComponent gripJ = 0;
GraphicsImportComponent gripG = 0;



SInt32 getOffsetToPayload( const Packet *packet )
{
#define kIPHeaderLength	20
	short tcpHeaderLength = (packet->dataOffsetAndJunk >> 2) & ~3;
	return kIPHeaderLength + tcpHeaderLength;
}

StashedPacket *addPacketToStash(const Packet *packetdata, SInt32 SOI, SInt32 EOI, StashedPacket *parent)
{
	
	ofLogNotice() << "addPacketToStash: " << endl;
	StashedPacket *p;
	
	if (!parent && SOI == -1)
	{ 
		ofLogNotice() << "addPacketToStash invalid packet" << endl;
		return NULL; 
	}
	if (packetdata->totalLength > kMaxPacketLength)
	{
		
		cout << "packetdata->totalLength: " << (int)packetdata->totalLength << " kMaxPacketLength: " << kMaxPacketLength <<  endl;
		return NULL;
		
	}
	
	p = &stash[nextStashEntry];
	if (p->state != kFree) 
	{ 
		ofLogNotice() << "addPacketToStash no free space" << endl;
		return(NULL); 
	}
	if (++nextStashEntry >= kStashSize) nextStashEntry = 0;
	
	p->state  = kCaptured;
	BlockMoveData(packetdata, p->data, packetdata->totalLength);
	p->payloadoffset = getOffsetToPayload(p->data);
	p->SOI    = SOI;
	p->EOI    = EOI;
	p->parent = parent;
	p->next   = NULL;
	p->following = NULL;
	
	if (parent)
	{
		p->next = parent->next;
		parent->next = p;
	}
	
	return(p);
}

void searchForImageMarkers(const Packet *packet, SInt32 *offsetOfSOI, SInt32 *offsetAfterEOI)
{
	
	UInt8 *packetStart, *dataStart, *dataEnd, *data;
	packetStart = (UInt8 *) packet;
	dataStart = packetStart + getOffsetToPayload(packet);	// first byte that might contain actual payload
	dataEnd = packetStart + packet->totalLength;	// byte after last byte that might contain actual payload
	
	*offsetOfSOI = -1;
	*offsetAfterEOI = -1;
	
	for( data = dataStart; data <= dataEnd-3; data++ ) {
		// JPEG SOI is FF D8, but it's always followed by another FF.
		if( ( 0xff == data[0] ) && ( 0xd8 == data[1] ) && ( 0xff == data[2] ) )
			*offsetOfSOI = data - packetStart;
		
		// GIF start marker is 'GIF89a' etc.
		if ('G' == data[0] && 'I' == data[1] && 'F' == data[2] && '8' == data[3])
			*offsetOfSOI = data - packetStart;
	}
	for( data = dataStart; data <= dataEnd-2; data++ ) {
		// JPEG EOI is always FF D9.
		if( ( 0xff == data[0] ) && ( 0xd9 == data[1] ) )
			*offsetAfterEOI = data - packetStart + 2; // caller will need to grab 2 extra bytes.
	}
	
	if (packet->moreFlagsAndJunk & kFINBit)
		*offsetAfterEOI = packet->totalLength;
}

StashedPacket *findParentPacket(const Packet *packet)
{
	int i;
	for (i = 0; i < kStashSize; i++)		// Search for matching packet
	{
		const Packet *p = stash[i].data;
		if (stash[i].state == kCaptured &&
			p->sourceIP   == packet->sourceIP   && p->destIP   == packet->destIP &&
			p->sourcePort == packet->sourcePort && p->destPort == packet->destPort)
		{
			// If this packet already has a parent, we share the same parent
			if (stash[i].parent) return (stash[i].parent);
			else return(&stash[i]);		// Else this packet is our parent
		}
	}
	return (NULL);
}

void TrimPacketChain(StashedPacket *p)
{
	StashedPacket *q;
	
	if (!p) return;
	
	// Free up to the next packet with a start marker
	do { p->state = kFree; p=p->next; } while (p && (p->SOI == -1));
	
	if (p)	// If we have packet with a start marker
	{
		for (q = p; q; q=q->next) q->parent = p;
		p->parent = NULL;
	}
}
int counter =0;
int createStash()
{
	int i;
	int returnValue = -1;
	for (i = 0; i < kStashSize; i++)
	{
		stash[i].state = kFree;
		stash[i].data = (Packet*)NewPtr(kMaxPacketLength);
		if (!stash[i].data) 
		{ 
			ofLogNotice() << "out of memory" << endl; 
			returnValue =  -1; 
		}else 
		{
			counter++;
			//ofLogNotice() << "STASH CREATED: " << counter << endl; 
			returnValue = 1;
		}
		
	}
	return returnValue;
}
// look for image-start markers more than 4 bytes into imageData.
// if one is found, remove the portion of the handle before it and return true.
// if none found, return false.
bool scanForAnotherImageMarker( Handle imageData )
{
	UInt8 *packetStart, *dataStart, *dataEnd, *data;
	Size handleSize = GetHandleSize( imageData );
	SInt32 offsetOfStart = -1L;
	
	packetStart = (UInt8*)imageData;
	dataStart = packetStart + 4;
	dataEnd = packetStart + handleSize;
	
	for( data = dataStart; data <= dataEnd-3; data++ ) {
		// JPEG SOI is FF D8, but it's always followed by another FF.
		if( ( 0xff == data[0] ) && ( 0xd8 == data[1] ) && ( 0xff == data[2] ) ) {
			offsetOfStart = data - packetStart;
			break;
		}
		
		// GIF start marker is 'GIF89a' etc.
		if ('G' == data[0] && 'I' == data[1] && 'F' == data[2] && '8' == data[3]) {
			offsetOfStart = data - packetStart;
			break;
		}
	}
	
	if( offsetOfStart > 0 ) {
		char mungerPleaseDelete;
		Munger( imageData, 0, nil, offsetOfStart, &mungerPleaseDelete, 0 );
		return true;
	}
	else {
		return false;
	}
}

void DisplayJPEGAndDisposeHandle( Handle imageData )
{
	OSErr err;
	Rect naturalBounds;
	MatrixRecord matrix;
	SInt32 gapH, gapV;
	Fixed scaleH, scaleV;
	Rect boundsRect;
	GraphicsImportComponent grip;
	Rect windowPortRect;
	static char gifSentinel[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
	static char jpegSentinel[] = {0xFF,0xD9,0xFF,0xD9,0xFF,0xD9,0xFF,0xD9,0xFF,0xD9,0xFF,0xD9,0xFF,0xD9,0xFF,0xD9};
	Ptr sentinel;
	Size sentinelSize;
	
	if( !imageData )
	{
		ofLogNotice() << "NO IMAGE DATA" << endl;
	}	else {
		
		ofImage image;
		//ofPixels pixels();
		//pixels = imageData;
		//image.setFromPixels((const unsigned char *)imageData);
		//string image
		//image.saveImage(ofToDataPath(ofGetTimestampString()+".jpg", OF_IMAGE_QUALITY_BEST));
		
		ofLogError() << "WE HAVE DATA!" << endl;
	}

	return;
	
again:
	
	ofLogError() << "Again called";
	if( 'G' == **imageData ) {
		grip = gripG;
		// for GIF:
		// FF FF FF FF will ensure that the bit parser aborts, since you can't
		// have two consecutive all-ones symbols in the LZW codestream --
		// you can sometimes have one (say, a 9-bit code), but after consuming
		// it the code width increases (so we're now using 10-bit codes) 
		// and the all-ones code won't be valid for a while yet.
		sentinel = gifSentinel;
		sentinelSize = sizeof(gifSentinel);
	}
	else {
		grip = gripJ;
		// for JPEG:
		// FF D9 FF D9 will ensure (a) that the bit-parser aborts, since FF D9
		// is an "unstuffed" FF and hence illegal in the entropy-coded datastream,
		// and (b) be long enough to stop overreads.
		sentinel = jpegSentinel;
		sentinelSize = sizeof(jpegSentinel);
	}
	
	//•• add sentinel pattern to the end of the handle.
	err = PtrAndHand( sentinel, imageData, sentinelSize );
	
	err = GraphicsImportSetDataHandle( grip, imageData );
	if( err )
	{
		
		ofLogNotice() << "GraphicsImportSetDataHandle Error" << endl;
		goto bail;
	}
	err = GraphicsImportGetNaturalBounds( grip, &naturalBounds );
	if( err )
	{
		
		ofLogNotice() << "GraphicsImportGetNaturalBounds Error" << endl;
		goto bail;
	}
	
	//GetPortBounds( GetWindowPort( window ), &windowPortRect );
	gapH = windowPortRect.right - naturalBounds.right;
	gapV = windowPortRect.bottom - naturalBounds.bottom;
	
	if( gapH >= 0 ) {
		gapH = ((UInt16)Random()) % gapH;
		scaleH = fixed1;
	}
	else {
		gapH = 0;
		scaleH = FixDiv( windowPortRect.right, naturalBounds.right );
	}
	
	if( gapV >= 0 ) {
		gapV = ((UInt16)Random()) % gapV;
		scaleV = fixed1;
	}
	else {
		gapV = 0;
		scaleV = FixDiv( windowPortRect.bottom, naturalBounds.bottom );
	}
	
	// need to use smaller scale of the two, and then recalc the other gap.
	if( scaleH > scaleV ) {
		scaleH = scaleV;
		gapH = windowPortRect.right - FixMul(scaleH, naturalBounds.right);
		gapH = ((UInt16)Random()) % gapH;
	} else if( scaleH < scaleV ) {
		scaleV = scaleH;
		gapV = windowPortRect.bottom - FixMul(scaleV, naturalBounds.bottom);
		gapV = ((UInt16)Random()) % gapV;
	}
	
	SetIdentityMatrix( &matrix );
	ScaleMatrix( &matrix, scaleH, scaleV, 0, 0 );
	TranslateMatrix( &matrix, gapH<<16, gapV<<16 );
	
	err = GraphicsImportSetMatrix( grip, &matrix );
	if( err ) goto bail;
	
	err = GraphicsImportDraw( grip );
	if( err ) goto bail;
	
	err = GraphicsImportGetBoundsRect( grip, &boundsRect );
	if( err ) goto bail;
	InsetRect( &boundsRect, -1, -1 );
	//SetPortWindowPort( window );
	FrameRect( &boundsRect );
	
	if( scanForAnotherImageMarker(imageData))
	{
		 ofLogError() << "again: scanForAnotherImageMarker" << endl;
		goto again;
	}
	
bail:
	DisposeHandle( imageData );

	//gDrewJPEG = true;
}

void harvestJPEG(StashedPacket *parent)
{
	
	ofLogNotice() << "harvestJPEG!" << endl;
	SInt32 totalSize;
	StashedPacket *p;
	Handle h;
	
	if (parent->SOI == -1) 
	{
		ofLogNotice() << "ERROR! parent packet has no SOI" << endl;
		return; 
	}
	
	totalSize = parent->payloadoffset - parent->SOI;
	if (parent->EOI != -1 && parent->EOI < parent->SOI) parent->EOI = -1;
	
	p = parent;
	while (p->EOI == -1)		// While we've not found the end, look for more in-order packets
	{
		StashedPacket *srch;
		SInt32 targetseqnum;
		totalSize += p->data->totalLength - p->payloadoffset;
		targetseqnum = p->data->sequenceNumber + p->data->totalLength - p->payloadoffset;
		for (srch = parent; srch; srch=srch->next)
			if (srch->data->sequenceNumber == targetseqnum)		// We found the right packet
			{
				if (srch->data->totalLength <= srch->payloadoffset) {
					// packets like this could cause us to hang, so skip 'em
					// printf("\pharvestJPEG: skipping empty payload");
					continue;
				}
				p->following = srch;							// Link it in
				p = srch;										// Move p one packet forward
				break;											// and continue
			}
		// If we couldn't find the desired sequence number, leave the chain in place
		// -- it might get completed later
		if (!srch) return;
	}
	
	totalSize += p->EOI - p->payloadoffset;
	h = NewHandle( totalSize );
	
	if( h ) {
		Ptr ptr = *h;
		
		SInt32 size = parent->data->totalLength - parent->SOI;
		if (parent->following == NULL) size += parent->EOI - parent->data->totalLength;
		BlockMoveData( ((Ptr)(parent->data)) + parent->SOI, ptr, size );
		ptr += size;
		
		p = parent->following;
		while (p)
		{
			size = p->data->totalLength - p->payloadoffset;
			if (p->following == NULL) size += p->EOI - p->data->totalLength;
			BlockMoveData( ((Ptr)(p->data)) + p->payloadoffset, ptr, size );
			ptr += size;
			p = p->following;
		}
		
		DisplayJPEGAndDisposeHandle(h);
	}else {
		ofLogNotice() << "out of memory, harvestJPEG" << endl;
	}

	//else printf("\p out of memory, harvestJPEG");
	
	TrimPacketChain(parent);
}


void ensureFreeSlotInStash()
{
	StashedPacket *p = &stash[nextStashEntry];
	
	if (p->state != kFree)
	{
		if (p->SOI != -1) harvestJPEG(p);
		while (p->state != kFree)		// If harvestJPEG was unable to pull a good image
		{								// out of the chain, then trash it anyway to make space
	 		TrimPacketChain(p->parent ? p->parent : p);
 		}
	}
}

int ConsumePacket( const Packet *packet )
{
	SInt32 SOI, EOI;
	StashedPacket *p;
	StashedPacket *parent;
	bool addMe = false;
	bool harvestMe = false;
	
	if( packet->protocol != 6 ) goto toss; // only TCP packets please
	if( ( packet->versionAndIHL & 0x0f ) != 5 ) goto toss; // minimal IP headers only (lame?)
	
	ensureFreeSlotInStash();
	
	p = NULL;
	parent = findParentPacket(packet);
	searchForImageMarkers(packet, &SOI, &EOI);
	
	if (parent) {
		ofLogNotice() << "WE HAVE PARENT" << endl;
	}
	if (SOI != -1) {
		ofLogNotice() << "WE HAVE SOI" << endl;
	}
	
	
	// If this packet contains an image start marker, or continues an existing sequence, then stash it
	
	
	if (parent || SOI != -1)
	{
		 addMe = true;
	}
	if (addMe)
	{
		 p = addPacketToStash(packet, SOI, EOI, parent);
	}
	if (EOI != -1) {
		ofLogNotice() << "WE HAVE EOI"  << endl;
	}
	// If this packet contains an image end marker, and we successfully stashed it, then harvest the packet
	if (p && EOI != -1) harvestMe = true;
	if (harvestMe) harvestJPEG(parent ? parent : p);
	
	if      (harvestMe) return(3); // blue
	else if (addMe)     return(2); // green
	else                return(1); // black
	return 1;
toss:
	return( 0 ); // yellow
}





void termPromiscuity(void)
{
	if( pcap_session ) {
		pcap_close( pcap_session );
		pcap_session = NULL;
	}
}
ofxEtherPEG::ofxEtherPEG()
{
	
}
void ofxEtherPEG::setup()
{
	
	
	int result = createStash();
	if (result == -1) {
		ofLogNotice() << "CREATE STASH FAILED" << endl;
	}
	char errorBuffer[PCAP_ERRBUF_SIZE];
	const char *device = INTERFACE; // should find all ethernet interfaces and open each
tryAgain:
	pcap_session = pcap_open_live( device, BUFSIZ, 1, 1, errorBuffer );
	if( pcap_session == NULL ) 
	{
		ofLogNotice() << "pcap failed" << endl;
	}else {
		ofLogNotice() << "pcap inited" << endl;
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
#if 0
		if (p->protocol != 6)
			printf("p->protocol != 6\n");
		else if ((p->versionAndIHL & 0x0F) != 5)
			printf("(p->versionAndIHL & 0x0F) != 5\n");
		else if ((p->totalLength < 40) && !(p->moreFlagsAndJunk & kFINBit))
			printf("(p->totalLength < 40) && !(p->moreFlagsAndJunk & kFINBit)\n");
#endif
		if ((p->protocol == 6) && ((p->versionAndIHL & 0x0F) == 5)) 
		{
			if ((p->totalLength > 40) || (p->moreFlagsAndJunk & kFINBit)) {
				createBlob(ConsumePacket( p ));
			}
			else createBlob( 0 ); // yellow
		}
		else createBlob( 0 ); // yellow
	}
}
void ofxEtherPEG::createBlob(int aNumber)
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
	if(xCounter>ofGetWidth())
	{
		xCounter = 0;
		rowCounter++;
	}else {
		xCounter+=BLOB_SIZE;
	}
	blob.x = xCounter;
	blob.y = rowCounter*BLOB_SIZE;
	blob.radius = BLOB_SIZE;
	blob.color = color;
	
	blobs.push_back(blob);
	if (rowCounter*BLOB_SIZE > ofGetHeight()) {
		blobs.clear();
		rowCounter = 0;
		xCounter = 0;
	}
	
}
void ofxEtherPEG::draw()
{
	ofPushStyle();
	
	
	
	if (blobs.size()>0) 
	{
		//int contentWidth = ( (4*blobs.size()) + (blobs.size()*2) );
		//int numRows = contentWidth/ofGetWidth();
		
		//ofLogNotice() << "numRows: " << numRows << endl;
		//ofLogNotice() << "contentWidth: " << contentWidth << endl;
		
		for (int i=0; i<blobs.size(); i++) 
		{
			ofSetColor(blobs[i].color);
			ofRect(blobs[i].x, blobs[i].y, blobs[i].radius, blobs[i].radius);

		}
		
		
		
		
	}
	ofPopStyle();
	/*for (int i=0; i<blobs.size(); i++) 
	{
		//ofSetRectMode(OF_RECTMODE_CORNER);
		ofSetColor(blobs[i].color);

		if (xCounter>ofGetWidth()) 
		{
			//ofLogNotice() << i << ": xCounter : " << xCounter << endl;
			xCounter = 0;
			rowCounter++;
			ofRect(xCounter, blobs[i].size*rowCounter, blobs[i].size, blobs[i].size);
		}else {
			xCounter+=(blobs[i].size*i) + (i*2);
		}
		ofLogNotice() << i << ": xCounter : " << xCounter << endl;

	}*/
	
	
}
