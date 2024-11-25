/*-----------------------------------------------------------------------------
   File:   vnscommand.h 
   Date:   Sat Apr 06 21:58:07 PST 2002 
   Contact:  casado@stanford.edu
  
   Description:
  
   A c-style declaration of commands for the virtual router.
  
  ---------------------------------------------------------------------------*/

#ifndef __VNSCOMMAND_H
#define __VNSCOMMAND_H

/* 
Note: Each message transmitted between client and server needs an identifier (mType) to
allow both sides to understand the purpose of the message.
Value like 1,2,4, 8... are chosen because they are power of 2 for checking of messages using bitwise AND operator
Example: 
    mType & VNSHWINFO → Non-zero result: contains `VNSHWINFO` message.
    mType & VNSPACKET → Non-zero result: contains `VNSPACKET` message.
*/

#define VNSOPEN       1         // Open connection to server (c_open)
#define VNSCLOSE      2         // CLose connection (c_close)
#define VNSPACKET     4         // Transmit packet (c_packet_ethernet_header)
#define VNSBANNER     8         // Receive a welcome message (c_banner)
#define VNSHWINFO    16         // Request hardware information (c_hwinfo)

#define IDSIZE 32

/*-----------------------------------------------------------------------------
                                 BASE
  ---------------------------------------------------------------------------*/

typedef struct
{
    uint32_t mLen;      /* Length of message */
    uint32_t mType;     /* Type of message */
}__attribute__ ((__packed__)) c_base;

/*-----------------------------------------------------------------------------
                                 OPEN
  ---------------------------------------------------------------------------*/

typedef struct 
{

    uint32_t mLen;
    uint32_t mType;         /* = VNSOPEN */
    uint16_t topoID;        /* Id of the topology we want to run on */
    uint16_t pad;           /* unused */
    char     mVirtualHostID[IDSIZE]; /* Id of the simulated router (e.g.
                                        'VNS-A'); */
    char     mUID[IDSIZE];  /* User id (e.g. "appenz"), for information only */
    char     mPass[IDSIZE]; /* Password */

}__attribute__ ((__packed__)) c_open;

/*-----------------------------------------------------------------------------
                                 CLOSE
  ---------------------------------------------------------------------------*/

typedef struct 
{

    uint32_t mLen; 
    uint32_t mType; 
    char     mErrorMessage[256]; /* Error message */

}__attribute__ ((__packed__)) c_close;

/*-----------------------------------------------------------------------------
                                HWREQUEST 
  ---------------------------------------------------------------------------*/

typedef struct 
{

    uint32_t mLen;
    uint32_t mType; 

}__attribute__ ((__packed__)) c_hwrequest;

/*-----------------------------------------------------------------------------
                                 BANNER 
  ---------------------------------------------------------------------------*/

typedef struct 
{

    uint32_t mLen; 
    uint32_t mType; 
    char     mBannerMessage[256];

}__attribute__ ((__packed__)) c_banner;

/*-----------------------------------------------------------------------------
                               PACKET (header)
  ---------------------------------------------------------------------------*/


typedef struct
{
    uint32_t mLen;
    uint32_t mType;
    char     mInterfaceName[16];    /*A null-terminated string representing the name of the network interface through which the packet was received or should be sent (e.g., eth0 for Ethernet).*/
    uint8_t  ether_dhost[6];        /*6 bytes representing the destination MAC address*/
    uint8_t  ether_shost[6];        /*6 bytes representing the source MAC address*/
    uint16_t ether_type;

}__attribute__ ((__packed__)) c_packet_ethernet_header;

typedef struct
{
    uint32_t mLen;
    uint32_t mType;
    char     mInterfaceName[16];
}__attribute__ ((__packed__)) c_packet_header;

/*-----------------------------------------------------------------------------
                               HWInfo 
  ----------------------------------------------------------------------------*/

#define HWINTERFACE    1    /* Interface name */
#define HWSPEED        2    /* Speed of hardware interface */
#define HWSUBNET       4    /* Subnet information */
#define HWINUSE        8    /* Indicates whether interface is in use */
#define HWFIXEDIP     16    /* Fixed IP address of the interface */
#define HWETHER       32    /* Ethernet hardware information */
#define HWETHIP       64    /* Ethernet IP address */
#define HWMASK       128    /* Subnet mask */

typedef struct
{
    uint32_t mKey;      /* Key representing the type of hardware information (e.g., interface, speed, etc.)*/
    char     value[32]; /* Value associated with the key (e.g., interface name, IP address, etc)*/
}__attribute__ ((__packed__)) c_hw_entry;

typedef struct
{
#define MAXHWENTRIES 256    /* Maximum number of hardware entries that can be stored*/
    uint32_t   mLen;
    uint32_t   mType;
    c_hw_entry mHWInfo[MAXHWENTRIES]; /* Array of hardware entries*/
}__attribute__ ((__packed__)) c_hwinfo;

/* ******* New VNS Messages ******** */
#define VNS_RTABLE        32            // Routing table (c_rtable)
#define VNS_OPEN_TEMPLATE 64            // Open a connection with a template (c_open_template)
#define VNS_AUTH_REQUEST 128            // Authentication request (c_auth_request)
#define VNS_AUTH_REPLY   256            // Authentication reply (c_auth_reply)
#define VNS_AUTH_STATUS  512            // Authentication status (c_auth_status)

/* rtable */
typedef struct
{
    uint32_t mLen;
    uint32_t mType;
    char     mVirtualHostID[IDSIZE];    
    char     rtable[0];                 /* Routing table (data server send) */
}__attribute__ ((__packed__)) c_rtable;

/* open template */
typedef struct {
    uint32_t ip;
    uint8_t  num_masked_bits;
}__attribute__ ((__packed__)) c_src_filter;

typedef struct
{
    uint32_t     mLen;
    uint32_t     mType;
    char         templateName[30];
    char         mVirtualHostID[IDSIZE];
    c_src_filter srcFilters[0];         /* Source filter */
}__attribute__ ((__packed__)) c_open_template;

/* authentication request */
typedef struct
{
    uint32_t mLen;
    uint32_t mType;
    uint8_t  salt[0];   /*Salt to encrypt */

}__attribute__ ((__packed__)) c_auth_request;

/* authentication reply */
typedef struct
{
    uint32_t mLen;
    uint32_t mType;
    uint32_t usernameLen;
    char     username[0];
    /* remainder of the message is the salted sha1 of the user's password */
}__attribute__ ((__packed__)) c_auth_reply;

/* authentication status (whether or not a reply was accepted) */
typedef struct
{
    uint32_t mLen;
    uint32_t mType;
    uint8_t  auth_ok;
    char     msg[0];    /* Flexible array for additional messages or error descriptions. */

}__attribute__ ((__packed__)) c_auth_status;


#endif  /* __VNSCOMMAND_H */
