// Modified DHCP (client) Library for CSE 4352 Project 1 & 2
// Rolando Rosales 1001850424

// DHCP Library
// Jason Losh

//-----------------------------------------------------------------------------
// Hardware Target
//-----------------------------------------------------------------------------

// Target Platform: -
// Target uC:       -
// System Clock:    -

// Hardware configuration:
// -

//-----------------------------------------------------------------------------
// Device includes, defines, and assembler directives
//-----------------------------------------------------------------------------

#include <stdio.h>
#include "dhcp.h"
#include "arp.h"
#include "timer.h"

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

#define DHCP_DISABLED   0
#define DHCP_INIT       1
#define DHCP_SELECTING  2
#define DHCP_REQUESTING 3
#define DHCP_TESTING_IP 4
#define DHCP_BOUND      5
#define DHCP_RENEWING   6
#define DHCP_REBINDING  7
#define DHCP_INITREBOOT 8 // not used since ip not stored over reboot
#define DHCP_REBOOTING  9 // not used since ip not stored over reboot

// ------------------------------------------------------------------------------
//  Globals
// ------------------------------------------------------------------------------

uint32_t xid = 0;
uint32_t leaseSeconds = 0;
uint32_t leaseT1 = 0;
uint32_t leaseT2 = 0;

// use these variables if you want
bool discoverNeeded = false;
bool requestNeeded = false;
bool releaseNeeded = false;

bool ipConflictDetectionMode = false;

uint8_t dhcpOfferedIpAdd[4];
uint8_t dhcpServerIpAdd[4];

uint8_t dhcpState = DHCP_DISABLED;
bool    dhcpEnabled = true;

// ------------------------------------------------------------------------------
//  Structures
// ------------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Subroutines
//-----------------------------------------------------------------------------

// State functions

void setDhcpState(uint8_t state)
{
    dhcpState = state;
}

uint8_t getDhcpState()
{
    return dhcpState;
}

// New address functions
// Manually requested at start-up
// Discover messages sent every 15 seconds

void callbackDhcpGetNewAddressTimer()
{
}

void requestDhcpNewAddress()
{
}

// Renew functions

void renewDhcp()
{
}

void callbackDhcpT1PeriodicTimer()
{
}

void callbackDhcpT1HitTimer()
{
}

// Rebind functions

void rebindDhcp()
{
}

void callbackDhcpT2PeriodicTimer()
{
}

void callbackDhcpT2HitTimer()
{
}

// End of lease timer
void callbackDhcpLeaseEndTimer()
{
}

// Release functions

void releaseDhcp()
{
}

// IP conflict detection

void callbackDhcpIpConflictWindow()
{
}

void requestDhcpIpConflictTest()
{
}

bool isDhcpIpConflictDetectionMode()
{
    return ipConflictDetectionMode;
}

// Lease functions

uint32_t getDhcpLeaseSeconds()
{
    return leaseSeconds;
}

// Determines whether packet is DHCP
// Must be a UDP packet
bool isDhcpResponse(etherHeader* ether)
{
    bool ok;
    return ok;
}

// Send DHCP message
void sendDhcpMessage(etherHeader *ether, uint8_t type)
{
    uint8_t i;
    uint32_t sum;
    uint16_t tmp16;
    uint16_t dhcpLength;
    uint8_t *optionsPtr;
    uint8_t localHwAddress[6];
    uint8_t localIpAddress[4];

    // Ether frame
    getEtherMacAddress(localHwAddress);
    getIpAddress(localIpAddress);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = 0xFF;
        ether->sourceAddress[i] = localHwAddress[i];
    }
    ether->frameType = htons(TYPE_IP);

    // IP header
    ipHeader* ip = (ipHeader*)ether->data;
    ip->rev = 0x4;
    ip->size = 0x5;
    ip->typeOfService = 0;
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = PROTOCOL_UDP;
    ip->headerChecksum = 0;
    for (i = 0; i < IP_ADD_LENGTH; i++)
    {
        ip->destIp[i] = 0xFF;
        ip->sourceIp[i] = 0;
    }
    uint8_t ipHeaderLength = ip->size * 4;

    // UDP header
    udpHeader* udp = (udpHeader*)((uint8_t*)ip + (ip->size * 4));
    udp->sourcePort = htons(68);
    udp->destPort = htons(67);

    // DHCP Frame
    dhcpFrame* dhcp = (dhcpFrame*)udp->data;

    /************* this is currently setup for a discover message *************/


    // These are  the fields common to all DHCP messages
    dhcp->op = 0x1;     // Boot Request
    dhcp->htype = 0x1;  // Ethernet
    dhcp->hlen = 0x6;   // MAC length
    dhcp->hops = 0x0;   // Hops
    dhcp->xid = htonl(0x07900000 + xid); // Transaction ID
    xid++;
    dhcp->secs = htons(0x0);  // Seconds
    dhcp->flags = htons(0x0); // Flags

    switch (type) {
        case DHCPDISCOVER:
            // Writing the first 240 bytes of the DHCP frame
            for (i = 0; i < 4; i++)
            {
                dhcp->ciaddr[i] = 0x0;  // Client IP
                dhcp->yiaddr[i] = 0x0;  // Your IP
                dhcp->siaddr[i] = 0x0;  // Server IP
                dhcp->giaddr[i] = 0x0;  // Gateway IP
            }

            for (i = 0; i < HW_ADD_LENGTH; i++)
            {
                dhcp->chaddr[i] = localHwAddress[i];    // Client MAC Address
            }

            for (i = 0; i < 192; i++)
            {
                dhcp->data[i] = 0x0;    // DHCP Data
            }

            dhcp->magicCookie = htonl(0x63825363);  // Magic Cookie

            // Writing the options field
            optionsPtr = dhcp->options;

            *(optionsPtr++) = 0x35; // Option: (53) DHCP Message Type (Discover)
            *(optionsPtr++) = 0x1;  // Length: 1
            *(optionsPtr++) = 0x1;  // DHCP: Discover (1)

            *optionsPtr = 0xFF;     // Option End: 255

            break;
        case DHCPOFFER:
            // Code for DHCPOFFER state
            break;
        case DHCPREQUEST:
            // Code for DHCPREQUEST state
            for (i = 0; i < 4; i++)
            {
                dhcp->ciaddr[i] = 0x0;  // Client IP
                dhcp->yiaddr[i] = 0x0;  // Your IP
                dhcp->siaddr[i] = 0x0;  // Server IP
                dhcp->giaddr[i] = 0x0;  // Gateway IP
            }

            for (i = 0; i < HW_ADD_LENGTH; i++)
            {
                dhcp->chaddr[i] = localHwAddress[i];    // Client MAC Address
            }

            for (i = 0; i < 192; i++)
            {
                dhcp->data[i] = 0x0;    // DHCP Data
            }
            
            dhcp->magicCookie = htonl(0x63825363);  // Magic Cookie

            optionsPtr = dhcp->options;

            uint8_t *routerIp = getDhcpOption(ether, 0x3, 1000);

            *(optionsPtr++) = 0x35; // Option: (53) DHCP Message Type (Request)
            *(optionsPtr++) = 0x1;  // Length: 1
            *(optionsPtr++) = 0x3;  // DHCP: Request (3)

            while(1);

            break;
        case DHCPDECLINE:
            // Code for DHCPDECLINE state
            break;
        case DHCPACK:
            // Code for DHCPACK state
            break;
        case DHCPNAK:
            // Code for DHCPNAK state
            break;
        case DHCPRELEASE:
            // Code for DHCPRELEASE state
            break;
        case DHCPINFORM:
            // Code for DHCPINFORM state
            break;
        default:
            // Code for unknown state
            break;
    }

    /****************** end of setup for a discover message ******************/

    // adjust lengths
    dhcpLength = sizeof(udpHeader) + sizeof(dhcpFrame) + sizeof(uint8_t)*((optionsPtr + 1) - dhcp->options);
    ip->length = htons(ipHeaderLength + dhcpLength);

    // 32-bit sum over ip header
    calcIpChecksum(ip);
    
    // set udp length
    udp->length = htons(dhcpLength);

    // 32-bit sum over pseudo-header
    sum = 0;
    sumIpWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;
    sumIpWords(&udp->length, 2, &sum);

    // add udp header
    udp->check = 0;
    sumIpWords(udp, dhcpLength, &sum);
    udp->check = getIpChecksum(sum);

    // send packet with size = ether + udp hdr + ip header + udp_size
    putEtherPacket(ether, sizeof(etherHeader) + ipHeaderLength + dhcpLength);
}

uint8_t* getDhcpOption(etherHeader *ether, uint8_t option, uint8_t* length)
{
    uint8_t *optionPtr = (uint8_t*)ether + 282;
    uint8_t optionLen = 0;
    while (*optionPtr != 0xFF)
    {
        if (*optionPtr == option)
        {
            return optionPtr + 1;
        }
        else
        {
            optionPtr++;
            optionLen = *optionPtr;

            optionPtr += optionLen + 1;
        }
    }
    return 0;
}

// Determines whether packet is DHCP offer response to DHCP discover
// Must be a UDP packet
bool isDhcpOffer(etherHeader *ether, uint8_t ipOfferedAdd[])
{
    bool ok;
    return ok;
}

// Determines whether packet is DHCP ACK response to DHCP request
// Must be a UDP packet
bool isDhcpAck(etherHeader *ether)
{
    bool ok;
    return ok;
}

// Handle a DHCP ACK
void handleDhcpAck(etherHeader *ether)
{
}

// Message requests

bool isDhcpDiscoverNeeded()
{
    return false;
}

bool isDhcpRequestNeeded()
{
    return false;
}

bool isDhcpReleaseNeeded()
{
    return false;
}

void sendDhcpPendingMessages(etherHeader *ether)
{
}

void processDhcpResponse(etherHeader *ether)
{
}

void processDhcpArpResponse(etherHeader *ether)
{
}

// DHCP control functions

void enableDhcp()
{
}

void disableDhcp()
{
}

bool isDhcpEnabled()
{
    return false;
}

