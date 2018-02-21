/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2008,2009 IITP RAS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Kirill Andreev <andreev@iitp.ru>
 *
 * 
 * By default this script creates m_xSize * m_ySize square grid topology with
 * IEEE802.11s stack installed at each node with peering management
 * and HWMP protocol.
 * The side of the square cell is defined by m_step parameter.
 * When topology is created, UDP ping is installed to opposite corners
 * by diagonals. packet size of the UDP ping and interval between two
 * successive packets is configurable.
 * 
 *  m_xSize * step
 *  |<--------->|
 *   step
 *  |<--->|
 *  * --- * --- * <---Ping sink  _
 *  | \   |   / |                ^
 *  |   \ | /   |                |
 *  * --- * --- * m_ySize * step |
 *  |   / | \   |                |
 *  | /   |   \ |                |
 *  * --- * --- *                _
 *  ^ Ping source
 *
 *  See also MeshTest::Configure to read more about configurable
 *  parameters.
 */


#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mesh-module.h"
#include "ns3/mobility-module.h"
#include "ns3/mesh-helper.h"
#include "ns3/mesh-module.h"
#include "ns3/wifi-phy.h"

#include "ns3/flow-monitor.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/random-variable.h"
#include "ns3/hwmp-protocol.h"
#include "ns3/arp-l3-protocol.h"
#include "ns3/flow-probe.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>

#include <cstdlib>
#include <string.h>

#include "n_eq_coord.h"
#include "n_eq_25.h"
#include "n_eq_36.h"
#include "n_eq_49.h"
#include "n_eq_64.h"
#include "n_eq_81.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("MultipleLeadMetersScript");

class MeshTest{
    public:
        /// Init test
        MeshTest ();
        
        /// Configure test from command line arguments
        void Configure (int argc, char ** argv);
        
        /// Run test
        int Run ();
    
        void SetShuffle(int i);
        
    private:
        int       m_xSize;
        int       m_ySize;
        int       lead1_odds_first_sent;
        int       lead1_odds_stop_time;
        double    m_step;
        double    m_randomStart;
        double    m_totalTime;
        double    m_packetInterval;
        uint16_t  lead_packetSize;
        uint16_t  meter_packetSize;
        uint32_t  m_nIfaces;
        bool      m_chan;
        bool      m_pcap;
        std::string m_stack;
        std::string m_root;
        std::string m_txrate;
        std::string m_input;
        int         m_node_num;
        int         m_ac;
        int         m_conn;
        int         m_shuffle;
        double      m_initstartLead0ToLead1;
        double      m_initstartLead1ToLead0;
        double      m_initstartLead0ToEvens;
        double      m_initstartLead1ToOdds;
        double      m_initstartEvensToLead0;
        double      m_initstartOddsToLead1;
        double      m_stopLead0ToLead1;
        double      m_stopLead1ToLead0;
        int         m_sink;
        std::string m_sinkIpAddress;
        bool        m_ActivateSecurityModule;
        std::string m_filename;
        bool        m_gridtopology;
        bool        m_randomTopology;
        std::string m_UdpTcpMode;
        int         m_arpOp;
        int         m_size;
        double      m_arpwait;
        bool        m_randomAppStart;
        int         m_typeOfOperation;
        int*        m_obfVector01;
        int*        m_obfVector10;
        int*        m_obfVector10_plus_obfVector01;
        int*        m_finalObfVector;
  
        vector< coordinates > nodeCoords; 

        //to calculate the lenght of the simulation
        float m_timeTotal, m_timeStart, m_timeEnd;
        
        /// List of network nodes
        NodeContainer nodes;
        
        /// List of all mesh point devices
        NetDeviceContainer meshDevices;
        
        //Addresses of interfaces:
        Ipv4InterfaceContainer interfaces;
        
        // MeshHelper. Report is not static methods
        MeshHelper mesh;

        vector< vector< int > > meshNeighbors; 

    private:
        /// Create nodes and setup their mobility
        void CreateNodes ();
        
        /// Install internet m_stack on nodes
        void InstallInternetStack ();
        
        /// Install applications
        void InstallApplicationLead0ToLead1();
        void InstallApplicationLead1ToLead0 ();
        void InstallApplicationLead0ToEvenMeters();
        void InstallApplicationLead1ToOddMeters ();
        void InstallApplicationEvenMetersToLead0 ();
        void InstallApplicationOddMetersToLead1 ();

        /// Print mesh devices diagnostics
        void Report ();

        // interface between Hwmp and ArpL3Protocol
        void InstallSecureArp ();
        
        void InitializeSinkArpTable ();
};

MeshTest::MeshTest () :
    m_xSize (2),
    m_ySize (2),
    m_step (100.0),
    m_randomStart (0.1),
    m_totalTime (50.0),
    //m_packetInterval (0.5),
    lead_packetSize (512),
    meter_packetSize (4),
    m_nIfaces (1),
    m_chan (true),
    m_pcap (false),
    m_stack ("ns3::Dot11sStack"),
    m_root ("00:00:00:00:00:01"),
    //  m_root ("ff:ff:ff:ff:ff:ff"),
    m_txrate ("150kbps"),
    m_node_num (0),
    m_ac (6),
    m_conn (0),
    m_shuffle (2),
    m_sink (0),
    m_sinkIpAddress ("10.1.1.1"),
    m_ActivateSecurityModule (false),
    m_gridtopology (true),
    m_UdpTcpMode ("tcp"),
    m_arpOp (1),
    m_arpwait (4), // default 1 s, 4s better since no failed node
    m_randomAppStart (false),
    m_typeOfOperation (1)
{}

void MeshTest::Configure (int argc, char *argv[]){
    CommandLine cmd;
    
    cmd.AddValue ("init-lead0tolead1", "Initial Starting time from Sink to SMs [5.4]", m_initstartLead0ToLead1);
    cmd.AddValue ("init-lead1tolead0", "Initial Starting time from SMs to Sink [45.4]", m_initstartLead1ToLead0);
    cmd.AddValue ("init-lead0toEvens", "Initial Starting time from SMs to Sink [45.4]", m_initstartLead0ToEvens);
    cmd.AddValue ("init-Lead1toOdds", "Initial Starting time from SMs to Sink [45.4]", m_initstartLead1ToOdds);
    cmd.AddValue ("init-EvenstoLead0", "Initial Starting time from SMs to Sink [45.4]", m_initstartEvensToLead0);
    cmd.AddValue ("init-OddstoLead1", "Initial Starting time from SMs to Sink [45.4]", m_initstartOddsToLead1);
    
    cmd.AddValue ("stop-lead0tolead1", "Initial Starting time from Sink to SMs [5.4]", m_stopLead0ToLead1);
    cmd.AddValue ("stop-lead1tolead0", "Initial Starting time from Sink to SMs [5.4]", m_stopLead1ToLead0);
    
    cmd.AddValue ("size", "Number of nodes in simulation", m_size);
    cmd.AddValue ("start",  "Maximum random start delay, seconds. [0.1 s]", m_randomStart);
    cmd.AddValue ("time",  "Simulation time, seconds [100 s]", m_totalTime);
    cmd.AddValue ("packet-interval",  "Interval between packets in UDP ping, seconds [0.001 s]", m_packetInterval);
    cmd.AddValue ("lead-packet-size",  "Size of packets in UDP ping", lead_packetSize);
    cmd.AddValue ("meter-packet-size",  "Size of packets in UDP ping", meter_packetSize);
    cmd.AddValue ("interfaces", "Number of radio interfaces used by each mesh point. [1]", m_nIfaces);
    cmd.AddValue ("channels",   "Use different frequency channels for different interfaces. [0]", m_chan);
    cmd.AddValue ("pcap",   "Enable PCAP traces on interfaces. [0]", m_pcap);
    cmd.AddValue ("stack",  "Type of protocol stack. ns3::Dot11sStack by default", m_stack);
    cmd.AddValue ("root", "Mac address of root mesh point in HWMP", m_root);
    cmd.AddValue ("txrate", "Mac address of root mesh point in HWMP", m_txrate);
    cmd.AddValue ("node", "Node sink", m_node_num);
    cmd.AddValue ("ac", "Access Class UP_BE=0, UP_BK=1, UP_VI=5, UP_VO=6", m_ac);
    cmd.AddValue ("conn", "Number of sending nodes [1]", m_conn); 
    cmd.AddValue ("shuffle", "Number of random shuffle [2]", m_shuffle);
    cmd.AddValue ("sink", "Sink node ID [0]", m_sink);
    cmd.AddValue ("sink-ip", "IP address of the default entry in ARP table", m_sinkIpAddress);
    cmd.AddValue ("step", "IP address of the default entry in ARP table", m_step);
    cmd.AddValue ("xSize", "IP address of the default entry in ARP table", m_xSize);
    cmd.AddValue ("ySize", "IP address of the default entry in ARP table", m_ySize);
    cmd.AddValue ("security","Activate Security Module [false]", m_ActivateSecurityModule);
    cmd.AddValue ("UdpTcp", "UDP or TCP mode [udp]", m_UdpTcpMode);
    cmd.AddValue ("topology", "Topology file to read in node positions", m_input);
    cmd.AddValue ("arp-op", "ARP operations : 1. Normal [default], 2. Creation only, 3. Maintenance ony, 4. All pre-install arp table", m_arpOp);
    cmd.AddValue ("wait-arp", "When this timeout expires, the cache entries will be scanned and entries in WaitReply state will resend ArpRequest unless MaxRetries has been exceeded, in which case the entry is marked dead [1s]", m_arpwait);
    cmd.AddValue ("random-start", "Random start of the application [false]", m_randomAppStart);
    cmd.AddValue ("random-topology", "Random start of the application [false]", m_randomTopology);
    cmd.AddValue ("type-op", "1 = sink to SM and SM to sink, 2 = sink to SM only, 3=SM to sink only", m_typeOfOperation);

    cmd.Parse (argc, argv);
    
    NS_LOG_DEBUG ("Grid:" << m_xSize << "*" << m_ySize);
    NS_LOG_DEBUG ("Simulation time: " << m_totalTime << " s");
}

void MeshTest::CreateNodes (){
    double m_txpower = 18.0; // dbm
    
    /*
    * Create m_ySize*m_xSize stations to form a grid topology
    */
    nodes.Create (m_ySize*m_xSize);
    
    // Configure YansWifiChannel, default ns3::NistErrorRateModel
    YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();

    wifiPhy.Set ("EnergyDetectionThreshold", DoubleValue (-89.0) );
    wifiPhy.Set ("CcaMode1Threshold", DoubleValue (-62.0) );
    wifiPhy.Set ("TxGain", DoubleValue (1.0) );
    wifiPhy.Set ("RxGain", DoubleValue (1.0) );
    wifiPhy.Set ("TxPowerLevels", UintegerValue (1) );
    wifiPhy.Set ("TxPowerEnd", DoubleValue (m_txpower) );
    wifiPhy.Set ("TxPowerStart", DoubleValue (m_txpower) );
    wifiPhy.Set ("RxNoiseFigure", DoubleValue (7.0) );

    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
    //  YansWifiChannelHelper wifiChannel;
    //  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
    //  wifiChannel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel","Exponent", StringValue ("2.7"));
    wifiPhy.SetChannel (wifiChannel.Create ());

    // Configure the parameters of the Peer Link
    Config::SetDefault ("ns3::dot11s::PeerLink::MaxBeaconLoss", UintegerValue (20));
    Config::SetDefault ("ns3::dot11s::PeerLink::MaxRetries", UintegerValue (4));
    Config::SetDefault ("ns3::dot11s::PeerLink::MaxPacketFailure", UintegerValue (5));

    // Configure the parameters of the HWMP
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::Dot11MeshHWMPnetDiameterTraversalTime", TimeValue (Seconds (2)));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::Dot11MeshHWMPactivePathTimeout", TimeValue (Seconds (100)));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::Dot11MeshHWMPactiveRootTimeout", TimeValue (Seconds (100)));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::Dot11MeshHWMPmaxPREQretries", UintegerValue (5));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::UnicastPreqThreshold",UintegerValue (10));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::UnicastDataThreshold",UintegerValue (5));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::DoFlag", BooleanValue (true));
    Config::SetDefault ("ns3::dot11s::HwmpProtocol::RfFlag", BooleanValue (false));

    if (m_arpwait != 1.0) {
        Config::SetDefault ("ns3::ArpCache::WaitReplyTimeout", TimeValue (Seconds (m_arpwait)));
    }
    
    //Configure the default entry of ARP table
    //Config::SetDefault ("ns3::dot11s::HwmpProtocol::ArpIP", Ipv4AddressValue (Ipv4Address (m_sinkIpAddress.c_str())));
    //Config::SetDefault ("ns3::dot11s::HwmpProtocol::ArpMac", Mac48AddressValue (Mac48Address (m_root.c_str ())));

    //Config::SetDefault ("ns3::SecureArp::ActivateSecurityModule", BooleanValue (m_ActivateSecurityModule));
    //Config::SetDefault ("ns3::dot11s::HwmpProtocol::ActivateSecurityModule", BooleanValue (m_ActivateSecurityModule));
   
    /*
     * Create mesh helper and set stack installer to it
     * Stack installer creates all needed protocols and install them to
     * mesh point device
     */
    mesh = MeshHelper::Default ();
    
    if (!Mac48Address (m_root.c_str ()).IsBroadcast ()){
        mesh.SetStackInstaller (m_stack, "Root", Mac48AddressValue (Mac48Address (m_root.c_str ())));
    }
    else{
        //If root is not set, we do not use "Root" attribute, because it
        //is specified only for 11s
        mesh.SetStackInstaller (m_stack);
    }
    
    if (m_chan){
        mesh.SetSpreadInterfaceChannels (MeshHelper::SPREAD_CHANNELS);
    }
    else{
        mesh.SetSpreadInterfaceChannels (MeshHelper::ZERO_CHANNEL);
    }
    
    mesh.SetStandard (WIFI_PHY_STANDARD_80211g);
    mesh.SetMacType ("RandomStart", TimeValue (Seconds(m_randomStart)));
    //mesh.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode", StringValue ("OfdmRate6Mbps"), "RtsCtsThreshold", UintegerValue (25000)); // for 802.11a
    mesh.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode", StringValue ("ErpOfdmRate6Mbps"), "RtsCtsThreshold", UintegerValue (2500));
 
    // Set number of interfaces - default is single-interface mesh point
    mesh.SetNumberOfInterfaces (m_nIfaces);
  
    // Install protocols and return container if MeshPointDevices
    meshDevices = mesh.Install (wifiPhy, nodes);

    // Setup mobility - static grid topology
    MobilityHelper mobility;
    
    if (!m_randomTopology) {
        mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                       "MinX", DoubleValue (0.0),
                                       "MinY", DoubleValue (0.0),
                                       "DeltaX", DoubleValue (m_step),
                                       "DeltaY", DoubleValue (m_step),
                                       "GridWidth", UintegerValue (m_xSize),
                                       "LayoutType", StringValue ("RowFirst"));

        for (int i = 0; i < m_xSize*m_ySize; i++){
            //case ROW_FIRST:
            coordinates position;
            position.X = m_step * (i % m_xSize);
            position.Y = m_step * (i / m_xSize);
            nodeCoords.push_back ( position );
        }
    }
    else { // random topology
        Ptr<ListPositionAllocator> position = new ListPositionAllocator();
        MobilityHelper mobility;
        NS_LOG_DEBUG("reading topology from file " << m_input);
        std::ifstream input;
        int i = 0;
        input.open(m_input.c_str());
        if (input.is_open()) 
        { 
          int j = 0;
          std::string line;
          while (input.good() && j < 4)
          {
            getline (input,line);
            //NS_LOG_DEBUG("ignoring input line " << line);
            ++j;
          } 
          std::string s1, s2, s3;

          i = 0;
          double x, y, z;   
          while (input.good() && i < m_size) 
          {
            input >> s1 >> s2 >> s3 >> x;
            input >> s1 >> s2 >> s3 >> y;
            input >> s1 >> s2 >> s3 >> z;
            position->Add(*new Vector3D (x,y,z));
            NS_LOG_DEBUG ("created node " << i << " at " << x << " " << y << " " << z);
            ++i;
          }
          input.close();
        } else {
          std::cerr << "Error: Can't open file " << m_input << "\n";
          exit (EXIT_FAILURE);    
        }
         mobility.SetPositionAllocator (position);
        /*int topoId = m_shuffle-1; 
        switch (m_xSize) {
            case 5:
                //  for (unsigned int i = 0; i < m_xSize*m_ySize; i++)
                for (unsigned int i = 0; i < sizeof array(n_eq_25[topoId]); i++)           
                    nodeCoords.push_back (n_eq_25[topoId][i]);
                break;
            case 6:
                for (unsigned int i = 0; i < sizeof array(n_eq_36[topoId]); i++)           
                    nodeCoords.push_back (n_eq_36[topoId][i]);
                break;
            case 7:
                for (unsigned int i = 0; i < sizeof array(n_eq_49[topoId]); i++)           
                    nodeCoords.push_back (n_eq_49[topoId][i]);
                break;
            case 8:
                for (unsigned int i = 0; i < sizeof array(n_eq_64[topoId]); i++)           
                    nodeCoords.push_back (n_eq_64[topoId][i]);
                break;
            case 9:
                for (unsigned int i = 0; i < sizeof array(n_eq_81[topoId]); i++)           
                    nodeCoords.push_back (n_eq_81[topoId][i]);
                break;
        }
        
        Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
        for (vector< coordinates >::iterator j = nodeCoords.begin (); j != nodeCoords.end (); j++){
            positionAlloc->Add (Vector ((*j).X, (*j).Y, 0.0));
        }
        mobility.SetPositionAllocator (positionAlloc);*/
    }
    mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
    mobility.Install (nodes);
    
    if (m_pcap)
        wifiPhy.EnablePcapAll (std::string ("mp-"));
}

void MeshTest::InstallInternetStack (){
    // Config::SetDefault ("ns3::TcpL4Protocol::VariableRTO", BooleanValue (true));
    InternetStackHelper internetStack;
    internetStack.Install (nodes);
    Ipv4AddressHelper address;
    address.SetBase ("10.1.1.0", "255.255.255.0");
    interfaces = address.Assign (meshDevices);
}

void MeshTest::InstallApplicationLead0ToLead1 (){
    NS_LOG_INFO ("InstallApplicationLead0ToLead1---girdi 1");
    /*
    int i =0;
    int displacement = 0;
    int *array = new int[m_ySize*m_xSize];
    for (int i = 0; i < m_ySize*m_xSize-1; i++) {
       if (i == m_sink) {
          displacement++;
       }
       array[i] = i+displacement;
    } 
    // shuffle twice, to make it more random
    i=0;
    for (int i = 0; i < m_shuffle; i++) {
      std::random_shuffle(array,array+(m_ySize*m_xSize-1));
    } */
 
    m_obfVector01 = (int*) calloc(m_xSize *m_ySize, sizeof(int));
   
    int m_dest=0, m_dest_port, m_source=0;
    m_dest=m_sink;
    m_dest_port = 9100;
    int i = 0;
    char num [3];
    char onoff [8];
    double duration;
    ApplicationContainer apps [1];
    UniformVariable rand_nodes (1,m_ySize*m_xSize-1);
    UniformVariable rand_port (9000,9100);
    UniformVariable rand_start (0.001, 0.009);
    
    std::ostringstream os;
    os << m_filename <<"-time.txt";
    std::ofstream of (os.str().c_str(), std::ios::out | std::ios::app);

    for (i = 0; i < 1; i++){
        //m_source = array[i];
        
	strcpy(onoff,"onoff");
	sprintf(num,"%d",i);
     	strcat(onoff,num);
 
        //Config::SetDefault ("ns3::OnOffTs::PacketSize", UintegerValue (m_packetSize));
       
        if (m_UdpTcpMode=="udp") {
            OnOffHelperMLM onoff ("ns3::UdpSocketFactory", Address (InetSocketAddress(interfaces.GetAddress (1), m_dest_port)));
            onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
            onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));

            onoff.SetAttribute("FirstSent", TimeValue (Seconds (10)));
            onoff.SetAttribute("TransMode", UintegerValue(0));
            onoff.SetAttribute("MeterSize",UintegerValue(m_ySize*m_xSize));
             
            ///onoff.SetAttribute ("DataRate", StringValue (m_drateSMsToSink));
            apps[i] = onoff.Install (nodes.Get(0));
         
            if (m_randomAppStart){
                //duration = rand_start.GetValue()+m_initstartSMsToSink;
            }
            else{
                //duration = m_initstartSMsToSink;
            }
            
            apps[i].Start (Seconds (duration));
            // apps[i].Stop (Seconds (m_totalTime+m_initstart));
            apps[i].Stop (Seconds (m_totalTime));   
        }
        else {
            OnOffHelperMLM onoff ("ns3::TcpSocketFactory", Address (InetSocketAddress(interfaces.GetAddress (1), m_dest_port)));
            onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
            onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
            ///onoff.SetAttribute ("DataRate", StringValue (m_drateSMsToSink));

            onoff.SetAttribute ("PacketSize", UintegerValue (meter_packetSize));
            NS_LOG_INFO("Lead0 To Lead1");
            //onoff.SetAttribute("FirstSent", TimeValue (Seconds (m_initstartLead0ToLead1)));
            onoff.SetAttribute("TransMode", UintegerValue(0));
            onoff.SetAttribute("MeterSize",UintegerValue(m_ySize*m_xSize));

            int meterSize= m_ySize*m_xSize;
            int obfsVector[meterSize];
             
            srand(time(0));
            for(int z = 0; z < meterSize; z++){
                obfsVector[z] = rand() % 40 + (-20); //-20 and 20  
                m_obfVector01[z] = obfsVector[z];
            } 
            
            std::stringstream values;
            values << meterSize<<"$";
            std::string star ="*";
            
            for(int z=0; z<meterSize; z++){
                values<< obfsVector[z]<<star;
            }
            
            std::string obfsValue = values.str();
 
            onoff.SetAttribute ("ObfsValues", StringValue (obfsValue));             
             
            apps[i] = onoff.Install (nodes.Get(0));
              
            if (m_randomAppStart){
                duration = rand_start.GetValue()+m_initstartLead0ToLead1;
            }
            else{
                duration = m_initstartLead0ToLead1;
            }
            
            apps[i].Start (Seconds (duration));
            apps[i].Stop (Seconds (m_stopLead0ToLead1));   

        }
        //
        of << m_ySize << "x" << m_xSize << " " << m_source << " " << (duration) << " " << m_shuffle << " " << m_sink << " " <<"\n";
    }
    of.close ();
    if (m_UdpTcpMode=="udp") {
        PacketSinkHelperTs sink ("ns3::UdpSocketFactory",InetSocketAddress (interfaces.GetAddress (m_dest), m_dest_port));
        ApplicationContainer receiver = sink.Install (nodes.Get (m_dest));
        receiver.Start (Seconds (0.1));
        receiver.Stop (Seconds (m_totalTime+20));
    }        
    else {
        PacketSinkHelperTs sink ("ns3::TcpSocketFactory",InetSocketAddress (interfaces.GetAddress (1), m_dest_port));
        ApplicationContainer receiver = sink.Install (nodes.Get (1));
        receiver.Start (Seconds (0.1));
        receiver.Stop (Seconds (m_stopLead0ToLead1+20)); 
    } 
    NS_LOG_INFO ("InstallApplicationLead0ToLead1---girdi 2");
}

void MeshTest::InstallApplicationLead1ToLead0 (){
    /*
    int i =0;
    int displacement = 0;
    int *array = new int[m_ySize*m_xSize];
    for (int i = 0; i < m_ySize*m_xSize-1; i++) {
       if (i == m_sink) {
          displacement++;
       }
       array[i] = i+displacement;
    }
    // shuffle twice, to make it more random
    i=0;
    for (int i = 0; i < m_shuffle; i++) {
      std::random_shuffle(array,array+(m_ySize*m_xSize-1));
    }
    */
    
    int m_dest = 0, m_dest_port;

    int i = 0;
    char num [3];
    char onoff [8];
    char psink [8];
    double m_starting_time;
    ApplicationContainer apps [m_ySize*m_xSize];
    ApplicationContainer receiver [m_ySize*m_xSize];
    //ApplicationContainer receiver [m_ySize*m_xSize-1];
    UniformVariable rand_nodes (1,m_ySize*m_xSize-1);
    UniformVariable rand_port (9000,9250);
    UniformVariable rand_start (0.001, 0.009);
    
    std::ostringstream os;
    os << m_filename <<"-time.txt";
    std::ofstream of (os.str().c_str(), std::ios::out | std::ios::app);

    m_obfVector10 = (int*) calloc(m_xSize *m_ySize, sizeof(int));
    m_finalObfVector = (int*) calloc(m_xSize *m_ySize, sizeof(int));

    for (i = 0; i < 1; i++){ 
        //m_dest = array[i]; 
        m_dest_port = rand_port.GetValue(); // pick a random port number
          
	strcpy(onoff,"onoff");
	sprintf(num,"%d",i);
     	strcat(onoff,num);
        strcpy(psink, "psink");
        strcat(psink,num);

        //Config::SetDefault ("ns3::OnOffTs::PacketSize", UintegerValue (m_packetSize));
        /* create (m_xSize*m_ySize-1) on-off applications at the sink nodes
           each on-off application is set to a specific node ID and port number   
        */
        if (m_UdpTcpMode=="udp") {
            // destination is the SMs node ID and port number
            OnOffHelperMLM onoff ("ns3::UdpSocketFactory", Address (InetSocketAddress(interfaces.GetAddress (0), m_dest_port)));
            onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
            onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
            // onoff.SetAttribute ("AccessClass",UintegerValue (UintegerValue(UP_BE)));
            ///onoff.SetAttribute ("DataRate", StringValue (m_drateSinkToSMs));

            onoff.SetAttribute("FirstSent", TimeValue (Seconds (10)));
            onoff.SetAttribute("TransMode", UintegerValue(0));
            onoff.SetAttribute("MeterSize",UintegerValue(m_ySize*m_xSize));
            apps[i] = onoff.Install (nodes.Get(m_sink));       
        }
        else {       
            OnOffHelperMLM onoff ("ns3::TcpSocketFactory", Address (InetSocketAddress(interfaces.GetAddress (0), m_dest_port)));
            onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
                               onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
            // onoff.SetAttribute ("AccessClass",UintegerValue (UintegerValue(UP_BE)));
            ///onoff.SetAttribute ("DataRate", StringValue (m_drateSinkToSMs));
            onoff.SetAttribute ("PacketSize", UintegerValue (lead_packetSize));
            NS_LOG_INFO("Lead1 To Lead0");
            //onoff.SetAttribute("FirstSent", TimeValue (Seconds (20)));
            onoff.SetAttribute("TransMode", UintegerValue(0));
            onoff.SetAttribute("MeterSize",UintegerValue(m_ySize*m_xSize));

            int meterSize= m_ySize*m_xSize;
            int obfsVector[meterSize];

            m_obfVector10_plus_obfVector01 = (int*) calloc(m_xSize *m_ySize, sizeof(int));

            for(int z = 0; z < meterSize; z++){
                obfsVector[z] = rand() % 40 + (-20); //-20 and 20        
                m_obfVector10[z] = obfsVector[z]; 
            }

            for(int y = 0; y < meterSize; y++){
                m_obfVector10_plus_obfVector01[y] =  m_obfVector10[y]+ m_obfVector01[y]; 
                NS_LOG_INFO("FINAL VALUE("<<y<<"): "<< m_obfVector10_plus_obfVector01[y]);
            }

            std::stringstream values;
            values << meterSize<<"$";
            std::string star ="*";
            
            for(int z=0; z<meterSize; z++){
                values<< obfsVector[z]<<star;
            }
             
            std::string obfsValue = values.str();
            onoff.SetAttribute ("ObfsValues", StringValue (obfsValue));
             
            apps[i] = onoff.Install (nodes.Get(1));       
        }

        // want to add a random start ?
        if (m_randomAppStart) {
            m_starting_time = rand_start.GetValue()+m_initstartLead1ToLead0;
        }
        else {
            m_starting_time = m_initstartLead1ToLead0;
        }
        
        apps[i].Start (Seconds (m_starting_time));
        apps[i].Stop (Seconds (m_stopLead1ToLead0));   
        
        // now create which SM will be the receiver
        if (m_UdpTcpMode=="udp") {
            PacketSinkHelperTs psink ("ns3::UdpSocketFactory",InetSocketAddress (interfaces.GetAddress (0), m_dest_port));
            receiver[i] = psink.Install (nodes.Get (0)); 
        }
        else {
            PacketSinkHelperTs psink ("ns3::TcpSocketFactory",InetSocketAddress (interfaces.GetAddress (0), m_dest_port));
            receiver[i] = psink.Install (nodes.Get (0)); 
        } 
 
	receiver[i].Start (Seconds (0.1));
        receiver[i].Stop (Seconds (m_stopLead1ToLead0+20));
        
        of << m_ySize << "x" << m_xSize << " " << (m_starting_time) << " " << " " << m_sink << " " << m_dest << " " << m_dest_port << " " <<"\n";
    }
    of.close ();
}

/* install many packetsink to nodes, and install many onoff apps in sink 
   then pair each packetsink of each node with onoff apps from sink
*/
void MeshTest::InstallApplicationLead1ToOddMeters (){
    NS_LOG_INFO ("InstallApplicationLead1ToOddMeters Girdi 1");

    /*int i =0;
    int displacement = 0;
    int *array = new int[m_ySize*m_xSize];
    for (int i = 0; i < m_ySize*m_xSize-1; i++) {
       if (i == m_sink) {
          displacement++;
       }
       array[i] = i+displacement;
    }
    // shuffle twice, to make it more random
    i=0;
    for (int i = 0; i < m_shuffle; i++) {
      std::random_shuffle(array,array+(m_ySize*m_xSize-1));
    }*/
    
    int m_dest=0, m_dest_port;

    int i = 0;
    char num [3];
    char onoff [8];
    char psink [8];
    double m_starting_time;
    ApplicationContainer apps [m_ySize*m_xSize];
    ApplicationContainer receiver [m_ySize*m_xSize];
    //ApplicationContainer receiver [m_ySize*m_xSize-1];

    UniformVariable rand_nodes (1,m_ySize*m_xSize-1);
    UniformVariable rand_port (9000,9250);
    UniformVariable rand_start (0.001, 0.009);
    
    std::ostringstream os;
    os << m_filename <<"-time.txt";
    std::ofstream of (os.str().c_str(), std::ios::out | std::ios::app);
    
    lead1_odds_first_sent = 30*((m_ySize*m_xSize/2)-1);
    lead1_odds_stop_time = m_initstartLead1ToOdds + lead1_odds_first_sent + 20*((m_ySize*m_xSize/2)-1);
    
    for (i = 3; i < m_ySize*m_xSize; i+=2){ 
        //m_dest = array[i]; 
        m_dest_port = rand_port.GetValue(); // pick a random port number
          
	strcpy(onoff,"onoff");
	sprintf(num,"%d",i);
     	strcat(onoff,num);
        strcpy(psink, "psink");
        strcat(psink,num);

        //Config::SetDefault ("ns3::OnOffTs::PacketSize", UintegerValue (m_packetSize));
        /* create (m_xSize*m_ySize-1) on-off applications at the sink nodes
           each on-off application is set to a specific node ID and port number   
         */
        if (m_UdpTcpMode=="udp") {
            // destination is the SMs node ID and port number
            OnOffHelperMLM onoff ("ns3::UdpSocketFactory", Address (InetSocketAddress(interfaces.GetAddress (0), m_dest_port)));
            onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
            onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
            // onoff.SetAttribute ("AccessClass",UintegerValue (UintegerValue(UP_BE)));
            ///onoff.SetAttribute ("DataRate", StringValue (m_drateSinkToSMs));
            onoff.SetAttribute("FirstSent", TimeValue (Seconds (10)));
            onoff.SetAttribute("TransMode", UintegerValue(1));
            onoff.SetAttribute("MeterSize",UintegerValue(m_ySize*m_xSize));
            apps[i] = onoff.Install (nodes.Get(m_sink));       
        }
        else {       
            OnOffHelperMLM onoff ("ns3::TcpSocketFactory", Address (InetSocketAddress(interfaces.GetAddress (i), m_dest_port)));
            onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
                               onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
            // onoff.SetAttribute ("AccessClass",UintegerValue (UintegerValue(UP_BE)));
            ///onoff.SetAttribute ("DataRate", StringValue (m_drateSinkToSMs));
            onoff.SetAttribute ("PacketSize", UintegerValue (lead_packetSize));
            
            NS_LOG_INFO("Lead1 To OddMeters");
            onoff.SetAttribute("FirstSent", TimeValue (Seconds (lead1_odds_first_sent)));
            onoff.SetAttribute("TransMode", UintegerValue(1));
            onoff.SetAttribute("MeterSize",UintegerValue(m_ySize*m_xSize));                    

            std::stringstream val;
            val<<1<<"$"<<m_obfVector10_plus_obfVector01[i]<<"*";
            std::string lead1_To_OddMeter_ObfsValue = val.str();

            onoff.SetAttribute ("ObfsValues", StringValue (lead1_To_OddMeter_ObfsValue));

            apps[i] = onoff.Install (nodes.Get(1));       
        }

        // want to add a random start ?
        if (m_randomAppStart) {
            m_starting_time = rand_start.GetValue()+m_initstartLead1ToOdds;
        }
        else {
            m_starting_time = m_initstartLead1ToOdds;
        }

        apps[i].Start (Seconds (m_starting_time));
        apps[i].Stop (Seconds (lead1_odds_stop_time));   
        
        // now create which SM will be the receiver
        if (m_UdpTcpMode=="udp") {
            PacketSinkHelperTs psink ("ns3::UdpSocketFactory",InetSocketAddress (interfaces.GetAddress (0), m_dest_port));
            receiver[i] = psink.Install (nodes.Get (0)); 
        }
        else {
            PacketSinkHelperTs psink ("ns3::TcpSocketFactory",InetSocketAddress (interfaces.GetAddress (i), m_dest_port));
            receiver[i] = psink.Install (nodes.Get (i)); 
        } 

        receiver[i].Start (Seconds (0.1));
        receiver[i].Stop (Seconds (lead1_odds_stop_time+20));
        
        of << m_ySize << "x" << m_xSize << " " << (m_starting_time) << " " << " " << m_sink << " " << m_dest << " " << m_dest_port << " " <<"\n";
    }
    of.close ();
        
    NS_LOG_INFO ("InstallApplicationLead1ToOddMeters Girdi 2");
}

void MeshTest::InstallApplicationOddMetersToLead1 (){
    /*int i =0;
    int displacement = 0;
    int *array = new int[m_ySize*m_xSize];
    for (int i = 0; i < m_ySize*m_xSize-1; i++) {
       if (i == m_sink) {
          displacement++;
       }
       array[i] = i+displacement;
    }
    // shuffle twice, to make it more random
    i=0;
    for (int i = 0; i < m_shuffle; i++) {
      std::random_shuffle(array,array+(m_ySize*m_xSize-1));
    }*/
 
    NS_LOG_INFO ("InstallApplicationOddMetersToLead1---girdi 1");
    
    int m_dest=0, m_dest_port, m_source=0;
    m_dest=m_sink;
    m_dest_port = 9100;
    int i = 0;
    char num [3];
    char onoff [8];
    double duration;
    ApplicationContainer apps [m_ySize*m_xSize];
    UniformVariable rand_nodes (1,m_ySize*m_xSize-1);
    UniformVariable rand_port (9000,9100);
    UniformVariable rand_start (0.001, 0.009);
    
    std::ostringstream os;
    os << m_filename <<"-time.txt";
   
    std::ofstream of (os.str().c_str(), std::ios::out | std::ios::app);
   
    for (i = 3; i < m_ySize*m_xSize; i+=2){
        //m_source = array[i];
           
	strcpy(onoff,"onoff");
	sprintf(num,"%d",i);
     	strcat(onoff,num);
 
        //Config::SetDefault ("ns3::OnOffTs::PacketSize", UintegerValue (m_packetSize));
       
        if (m_UdpTcpMode=="udp") {
            OnOffHelperMLM onoff ("ns3::UdpSocketFactory", Address (InetSocketAddress(interfaces.GetAddress (m_dest), m_dest_port)));
            onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
	    onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
            ///onoff.SetAttribute ("DataRate", StringValue (m_drateSMsToSink));
            onoff.SetAttribute("FirstSent", TimeValue (Seconds (45)));
            onoff.SetAttribute("TransMode", UintegerValue(2));
            onoff.SetAttribute("MeterSize",UintegerValue(m_ySize*m_xSize));
            apps[i] = onoff.Install (nodes.Get(0));
            
            if (m_randomAppStart){
                //duration = rand_start.GetValue()+m_initstartSMsToSink;
            }
            else{
                //duration = m_initstartSMsToSink;
            }
            apps[i].Start (Seconds (duration));
            // apps[i].Stop (Seconds (m_totalTime+m_initstart));
            apps[i].Stop (Seconds (m_totalTime));
        }
        else {
            OnOffHelperMLM onoff ("ns3::TcpSocketFactory", Address (InetSocketAddress(interfaces.GetAddress (1), m_dest_port)));
            onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
            onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
            ///onoff.SetAttribute ("DataRate", StringValue (m_drateSMsToSink));
            onoff.SetAttribute ("PacketSize", UintegerValue (meter_packetSize));

            onoff.SetAttribute("FirstSent", TimeValue (Seconds (45)));
            onoff.SetAttribute("TransMode", UintegerValue(2));
            onoff.SetAttribute("MeterSize",UintegerValue(m_ySize*m_xSize));

            NS_LOG_INFO("---------OddMeters To Lead1--------");
            int number = rand() % 50 + (50);
            m_finalObfVector[i]= m_obfVector10_plus_obfVector01[i] + number;
            std::stringstream val;
            val<<1<<"$"<<m_finalObfVector[i]<<"*";
            std::string OddMetersToLead1 = val.str();
            onoff.SetAttribute ("ObfsValues", StringValue (OddMetersToLead1)); 

            apps[i] = onoff.Install (nodes.Get(i /*m_source*/));
            
            if (m_randomAppStart){
                duration = rand_start.GetValue()+m_initstartOddsToLead1;
            }
            else{
                duration = m_initstartOddsToLead1;
            }
            
            apps[i].Start (Seconds (duration));
            apps[i].Stop (Seconds (m_totalTime));   
        }
        of << m_ySize << "x" << m_xSize << " " << m_source << " " << (duration) << " " << m_shuffle << " " << m_sink << " " <<"\n";
    }
  
    of.close ();
    if (m_UdpTcpMode=="udp") {
        PacketSinkHelperTs sink ("ns3::UdpSocketFactory",InetSocketAddress (interfaces.GetAddress (0), m_dest_port));
        ApplicationContainer receiver = sink.Install (nodes.Get (0));
        receiver.Start (Seconds (0.1));
        receiver.Stop (Seconds (m_totalTime+20));
    }        
    else {
        PacketSinkHelperTs sink ("ns3::TcpSocketFactory",InetSocketAddress (interfaces.GetAddress (1), m_dest_port));
        ApplicationContainer receiver = sink.Install (nodes.Get (1));
        receiver.Start (Seconds (0.1));
        receiver.Stop (Seconds (m_totalTime+20)); 
    }
    NS_LOG_INFO ("InstallApplicationOddMetersToLead1---girdi 2");
}

void MeshTest::InstallApplicationEvenMetersToLead0 (){
    /*int i =0;
    int displacement = 0;
    int *array = new int[m_ySize*m_xSize];
    for (int i = 0; i < m_ySize*m_xSize-1; i++) {
       if (i == m_sink) {
          displacement++;
       }
       array[i] = i+displacement;
    }
    // shuffle twice, to make it more random
    i=0;
    for (int i = 0; i < m_shuffle; i++) {
      std::random_shuffle(array,array+(m_ySize*m_xSize-1));
    } */
 
    NS_LOG_INFO ("InstallApplicationEvenMetersToLead0---girdi 1");
    
    int m_dest=0, m_dest_port, m_source=0;
    m_dest=m_sink;
    m_dest_port = 9100;
    int i = 0;
    char num [3];
    char onoff [8];
    double duration;
    ApplicationContainer apps [m_ySize*m_xSize];
    UniformVariable rand_nodes (1,m_ySize*m_xSize-1);
    UniformVariable rand_port (9000,9100);
    UniformVariable rand_start (0.001, 0.009);
    
    std::ostringstream os;
    os << m_filename <<"-time.txt";
   
    std::ofstream of (os.str().c_str(), std::ios::out | std::ios::app);
  
    for (i = 2; i < m_ySize*m_xSize; i+=2){
        //m_source = array[i];
        
	strcpy(onoff,"onoff");
	sprintf(num,"%d",i);
     	strcat(onoff,num);
        
        //Config::SetDefault ("ns3::OnOffTs::PacketSize", UintegerValue (m_packetSize));
       
        if (m_UdpTcpMode=="udp") {
            OnOffHelperMLM onoff ("ns3::UdpSocketFactory", Address (InetSocketAddress(interfaces.GetAddress (0), m_dest_port)));
            onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
            onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
            ///onoff.SetAttribute ("DataRate", StringValue (m_drateSMsToSink));
            onoff.SetAttribute("FirstSent", TimeValue (Seconds (45)));
            onoff.SetAttribute("TransMode", UintegerValue(2));
            onoff.SetAttribute("MeterSize",UintegerValue(m_ySize*m_xSize));
            apps[i] = onoff.Install (nodes.Get(0));
         
            if (m_randomAppStart){
                duration = rand_start.GetValue()+m_initstartEvensToLead0;
            }
            else{
                duration = m_initstartEvensToLead0;
            }
            
            apps[i].Start (Seconds (duration));
            // apps[i].Stop (Seconds (m_totalTime+m_initstart));
            apps[i].Stop (Seconds (m_totalTime));   
        }
        else {
            OnOffHelperMLM onoff ("ns3::TcpSocketFactory", Address (InetSocketAddress(interfaces.GetAddress (0), m_dest_port)));
            onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
            onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
            ///onoff.SetAttribute ("DataRate", StringValue (m_drateSMsToSink));
            onoff.SetAttribute ("PacketSize", UintegerValue (meter_packetSize));
            onoff.SetAttribute("FirstSent", TimeValue (Seconds (45)));
            onoff.SetAttribute("TransMode", UintegerValue(2));
            onoff.SetAttribute("MeterSize",UintegerValue(m_ySize*m_xSize));

            NS_LOG_INFO("---------EvenMeters To Lead0--------");
            int number = rand() % 50 + (50);
            m_finalObfVector[i]= m_obfVector10_plus_obfVector01[i] + number;
            std::stringstream val;
            val<<1<<"$"<<m_finalObfVector[i]<<"*";
            std::string EvenMetersToLead0 = val.str();
            onoff.SetAttribute ("ObfsValues", StringValue (EvenMetersToLead0)); 

            apps[i] = onoff.Install (nodes.Get(i)); 
           
            if (m_randomAppStart){
                // NS_LOG_INFO("1");
                duration = rand_start.GetValue()+m_initstartEvensToLead0;
                //NS_LOG_INFO("2");
            }
            else{
                //NS_LOG_INFO("3");
                duration = m_initstartEvensToLead0;
                //NS_LOG_INFO("4");
            }
            
            apps[i].Start (Seconds (duration));
            //NS_LOG_INFO("5");
            apps[i].Stop (Seconds (m_totalTime));   

            //NS_LOG_INFO("6");
        }
        //
        //NS_LOG_INFO("7");
        of << m_ySize << "x" << m_xSize << " " << m_source << " " << (duration) << " " << m_shuffle << " " << m_sink << " " <<"\n";
        //NS_LOG_INFO("8");
    }
    //NS_LOG_INFO("For Dongusu bitti");
    of.close ();
       
    if (m_UdpTcpMode=="udp") {
        PacketSinkHelperTs sink ("ns3::UdpSocketFactory",InetSocketAddress (interfaces.GetAddress (m_dest), m_dest_port));
        ApplicationContainer receiver = sink.Install (nodes.Get (m_dest));
        receiver.Start (Seconds (0.1));
        receiver.Stop (Seconds (m_totalTime+20));
    }        
    else {
        //NS_LOG_INFO("c");
	PacketSinkHelperTs sink ("ns3::TcpSocketFactory",InetSocketAddress (interfaces.GetAddress (0), m_dest_port));
        //NS_LOG_INFO("d");
        ApplicationContainer receiver = sink.Install (nodes.Get (0));
        //NS_LOG_INFO("e");
        receiver.Start (Seconds (0.1));
        //NS_LOG_INFO("f");
        receiver.Stop (Seconds (m_totalTime+20));
        //NS_LOG_INFO("g");
    } 
    NS_LOG_INFO ("InstallApplicationEvenMetersToLead0---girdi 2");
}

void MeshTest::InstallApplicationLead0ToEvenMeters (){
    NS_LOG_INFO ("InstallApplicationLead0ToEvenMeters Girdi 1");
    
    /*
    int i =0;
    int displacement = 0;
    int *array = new int[m_ySize*m_xSize];
    for (int i = 0; i < m_ySize*m_xSize-1; i++) {
       if (i == m_sink) {
          displacement++;
       }
       array[i] = i+displacement;
    }
    // shuffle twice, to make it more random
    i=0;
    for (int i = 0; i < m_shuffle; i++) {
      std::random_shuffle(array,array+(m_ySize*m_xSize-1));
    }
    */
    
    int m_dest=0;
    int m_dest_port;

    int i = 0;
    char num [3];
    char onoff [8];
    char psink [8];
    double m_starting_time;
    ApplicationContainer apps [m_ySize*m_xSize];
    ApplicationContainer receiver [m_ySize*m_xSize];
    //ApplicationContainer receiver [m_ySize*m_xSize-1];

    UniformVariable rand_nodes (1,m_ySize*m_xSize-1);
    UniformVariable rand_port (9000,9250);
    UniformVariable rand_start (0.001, 0.009);
    
    std::ostringstream os;
    os << m_filename <<"-time.txt";
    std::ofstream of (os.str().c_str(), std::ios::out | std::ios::app);
    
    for (i = 2; i < m_ySize*m_xSize; i+=2){ 
        //m_dest = array[i]; 
        m_dest_port = rand_port.GetValue(); // pick a random port number
          
	strcpy(onoff,"onoff");
	sprintf(num,"%d",i);
     	strcat(onoff,num);
        strcpy(psink, "psink");
        strcat(psink,num);

        //Config::SetDefault ("ns3::OnOffTs::PacketSize", UintegerValue (m_packetSize));
        /* create (m_xSize*m_ySize-1) on-off applications at the sink nodes
           each on-off application is set to a specific node ID and port number   
        */
        if (m_UdpTcpMode=="udp") {
            // destination is the SMs node ID and port number
            OnOffHelperMLM onoff ("ns3::UdpSocketFactory", Address (InetSocketAddress(interfaces.GetAddress (i), m_dest_port)));
            onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
            onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
            // onoff.SetAttribute ("AccessClass",UintegerValue (UintegerValue(UP_BE)));
            ///onoff.SetAttribute ("DataRate", StringValue (m_drateSinkToSMs));

            onoff.SetAttribute("FirstSent", TimeValue (Seconds (30)));
            onoff.SetAttribute("TransMode", UintegerValue(1));
            onoff.SetAttribute("MeterSize",UintegerValue(m_ySize*m_xSize));
            apps[i] = onoff.Install (nodes.Get(m_sink));       
        }
        else {       
            OnOffHelperMLM onoff ("ns3::TcpSocketFactory", Address (InetSocketAddress(interfaces.GetAddress (i), m_dest_port)));
            onoff.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
                               onoff.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
            // onoff.SetAttribute ("AccessClass",UintegerValue (UintegerValue(UP_BE)));
            ///onoff.SetAttribute ("DataRate", StringValue (m_drateSinkToSMs));
            onoff.SetAttribute ("PacketSize", UintegerValue (lead_packetSize));


            NS_LOG_INFO("Lead0 To EvenMeters");
            onoff.SetAttribute("FirstSent", TimeValue (Seconds (30)));
            onoff.SetAttribute("TransMode", UintegerValue(1));
            onoff.SetAttribute("MeterSize",UintegerValue(m_ySize*m_xSize));                    

            std::stringstream val;
            val<<1<<"$"<<m_obfVector10_plus_obfVector01[i]<<"*";
            std::string leadO_To_EvenMeter_ObfsValue = val.str();

            onoff.SetAttribute ("ObfsValues", StringValue (leadO_To_EvenMeter_ObfsValue));

            apps[i] = onoff.Install (nodes.Get(0));       
        }
       
        //
        // want to add a random start ?
        if (m_randomAppStart) {
            m_starting_time = rand_start.GetValue()+m_initstartLead0ToEvens;
        }
        else {
            m_starting_time = m_initstartLead0ToEvens;
        }
        
        apps[i].Start (Seconds (m_starting_time));
        apps[i].Stop (Seconds (m_totalTime));   
        
        // now create which SM will be the receiver
        if (m_UdpTcpMode=="udp") {
            PacketSinkHelperTs psink ("ns3::UdpSocketFactory",InetSocketAddress (interfaces.GetAddress (m_dest), m_dest_port));
            receiver[i] = psink.Install (nodes.Get (m_dest)); 
        }
        else {
            PacketSinkHelperTs psink ("ns3::TcpSocketFactory",InetSocketAddress (interfaces.GetAddress (i), m_dest_port));
            receiver[i] = psink.Install (nodes.Get (i)); 
        } 

        receiver[i].Start (Seconds (0.1));
        receiver[i].Stop (Seconds (m_totalTime+20));
        
        of << m_ySize << "x" << m_xSize << " " << (m_starting_time) << " " << " " << m_sink << " " << m_dest << " " << m_dest_port << " " <<"\n";
    }
    of.close ();
      
    NS_LOG_INFO ("InstallApplicationLead0ToEvenMeters Girdi 2");
}

void MeshTest::InitializeSinkArpTable (){
    typedef std::pair<Mac48Address, Ipv4Address> AddressMapping;
    int x = 0;
    Mac48Address mac;
    Ptr<NetDevice> nd_sink;
    Ptr<MeshPointDevice> mp_sink;
    std::vector <AddressMapping> m_initArp;
    std::vector <AddressMapping> m_ArpSink;
    for (NetDeviceContainer::Iterator i = meshDevices.Begin (); i != meshDevices.End (); ++i){
        Ptr<MeshPointDevice> mp = (*i)->GetObject<MeshPointDevice> ();
        Ptr<NetDevice> nd = *i;
        mac = Mac48Address::ConvertFrom (mp->GetAddress () );
        AddressMapping arp;
        if (mac != Mac48Address (m_root.c_str () ) ) {
            arp = std::make_pair (Mac48Address::ConvertFrom (mp->GetAddress () ), interfaces.GetAddress (x) );
            m_initArp.push_back (arp);
            //   std::cout << Mac48Address::ConvertFrom (mp->GetAddress ()) << "," << interfaces.GetAddress (x) << std::endl;
        }
        else{
            mp_sink = mp;
            nd_sink = nd;
            arp = std::make_pair (Mac48Address::ConvertFrom (mp->GetAddress () ), interfaces.GetAddress (x) );
            m_ArpSink.push_back (arp);
        }
        x++;
    }
    
    // initialize arp table of sink
    Ptr<Node> node = mp_sink->GetNode () ;
    Ptr<ArpL3Protocol> arpL3 = node->GetObject<ArpL3Protocol> ();
    Ptr<ArpCache> arpcache = arpL3->FindCache (nd_sink);
    
    switch (m_arpOp) {
        case 2:  // creation phase only
            arpcache->SetAliveTimeout(Seconds (1000));
            break;
        case 3: // maintenance phase only
            for (long index = 0; index < (long) m_initArp.size (); index++ ){
                ArpCache::Entry *entry = arpcache->Lookup (m_initArp.at(index).second);
                if (entry == 0 ){
                    NS_LOG_LOGIC ("Add new entry to the ARP cache" );
                    entry = arpcache->Add (m_initArp.at(index).second);
                }
                entry->SetMacAddress (m_initArp.at(index).first);
            }
            break;
        case 4: // all pre-install, no arp broadcast request
            arpcache->SetAliveTimeout(Seconds (1000));
            for (long index = 0; index < (long) m_initArp.size (); index++ ){
                ArpCache::Entry *entry = arpcache->Lookup (m_initArp.at(index).second);
                if (entry == 0 ){
                    NS_LOG_LOGIC ("Add new entry to the ARP cache" );
                    entry = arpcache->Add (m_initArp.at(index).second);
                }
                entry->SetMacAddress (m_initArp.at(index).first);
            }     
            break;
    }
    
    // initialize arp table on every SMs
    for (NetDeviceContainer::Iterator i = meshDevices.Begin (); i != meshDevices.End (); ++i) {
        Ptr<MeshPointDevice> mp = (*i)->GetObject<MeshPointDevice> ();    
        if (Mac48Address::ConvertFrom (mp->GetAddress () ) != Mac48Address (m_root.c_str () ) ) {
            Ptr<NetDevice> nd = *i;
            Ptr<Node> node = mp->GetNode ();
            Ptr<ArpL3Protocol> arpL3 = node->GetObject<ArpL3Protocol> ();
            Ptr<ArpCache> arpcache = arpL3->FindCache (nd);
            
            switch (m_arpOp) {
                case 2: //creation phase only
                    arpcache->SetAliveTimeout(Seconds (1000));
                    break;
                case 3: // maintenance phase only
                    for (long index = 0; index < (long) m_ArpSink.size (); index++ ) {
                        ArpCache::Entry *entry = arpcache->Lookup (m_ArpSink.at(index).second);
                        if (entry == 0 ) {
                            NS_LOG_LOGIC ("Add new entry to the ARP cache" );
                            entry = arpcache->Add (m_ArpSink.at(index).second);
                        }
                        entry->SetMacAddress (m_ArpSink.at(index).first);
                    }
                    break;
                case 4: // pre-configure all
                    arpcache->SetAliveTimeout(Seconds (1000));
                    for (long index = 0; index < (long) m_ArpSink.size (); index++ ) {
                        ArpCache::Entry *entry = arpcache->Lookup (m_ArpSink.at(index).second);
                        if (entry == 0 ) {
                            NS_LOG_LOGIC ("Add new entry to the ARP cache" );
                            entry = arpcache->Add (m_ArpSink.at(index).second);
                        }
                        entry->SetMacAddress (m_ArpSink.at(index).first);
                    }
                    break;
            }         
        }
    }
}

int MeshTest::Run (){
    Packet::EnablePrinting();
    std::ostringstream tmp;
   // std::ostringstream tmpTopology;
    tmp << "two-ways-" << m_typeOfOperation << "-";

    if (m_gridtopology) {
        tmp << "grid-"<<m_initstartLead0ToLead1<<"-";
    }
    else 
        tmp <<m_xSize << "x" << m_ySize << "-"<<m_initstartLead0ToLead1<<"-";

    if (m_randomAppStart)
        tmp << "randStart-";

    switch (m_arpOp) {
        case 2:
            tmp << "cpo-";
            break;
        case 3:
            tmp << "mpo-";
            break;
        case 4:
            tmp << "na-";
            break;
    } 
  
    m_filename = tmp.str () ;
    CreateNodes ();

    if (!m_gridtopology) {
        std::ostringstream osp;
        osp << m_filename <<"-pos.txt";
        std::ofstream osf (osp.str().c_str(), std::ios::out | std::ios::app);
        
        for (NodeContainer::Iterator j = nodes.Begin(); j != nodes.End(); ++j) {
            Ptr<Node> object = *j;
            Ptr<MobilityModel> position = object->GetObject<MobilityModel> ();
            Vector pos = position->GetPosition();
            osf << m_xSize << "x" << m_ySize << " x=" << pos.x << ", y=" << pos.y << " " << m_shuffle << "\n";
        }
        osf.close();
    }
    
    InstallInternetStack ();
    if (m_arpOp!=1) { // normal operation, let arp table empty
        InitializeSinkArpTable ();
    }
  
    //  InstallSecureArp ();
    // Install
    switch (m_typeOfOperation) {
        case 1:    
            InstallApplicationLead0ToLead1(); // transMode=0
            InstallApplicationLead1ToLead0 (); //transmode=0
            InstallApplicationLead1ToOddMeters (); //transMode =1
            //InstallApplicationLead0ToEvenMeters(); //transMode =1
            //InstallApplicationOddMetersToLead1 (); // transMode=2
            //InstallApplicationEvenMetersToLead0 (); // transMode=2
            break;
        case 2:
            InstallApplicationLead1ToOddMeters ();
            InstallApplicationLead0ToEvenMeters();
            InstallApplicationLead1ToLead0 ();
            break;
        case 3:
            InstallApplicationOddMetersToLead1 ();
            InstallApplicationEvenMetersToLead0 ();
            InstallApplicationLead0ToLead1();
            break;
    }
  
    //  NS_LOG_INFO ("girdi2");
    //  Config::SetDefault ("ns3::OnOffTs::FirstSent", TimeValue (Seconds (m_initstart2)));

    // Install FlowMonitor on all nodes
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();
    m_timeStart=clock();
    Simulator::Schedule (Seconds (m_totalTime), &MeshTest::Report, this);
    Simulator::Stop (Seconds (m_totalTime));
    Simulator::Run ();
    
    if (m_UdpTcpMode=="udp") {
        // Define variables to calculate the metrics
	int k=0;
	int totaltxPackets = 0;
	int totalrxPackets = 0;
	double totaltxbytes = 0;
	double totalrxbytes = 0;
	double totaldelay = 0;
	double totalrxbitrate = 0;
        double throughput_total = 0;
        double throughput_total2 = 0;
	double difftx, /*diffrx,*/ diffrxtx;
	double pdf_value, rxbitrate_value, txbitrate_value, delay_value, throughput_value, throughput_value2;
	double pdf_total, rxbitrate_total, delay_total;

	//Print per flow statistics
	monitor->CheckForLostPackets ();
        //monitor->CheckForLostPackets(Seconds(0.001));
	Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>
	(flowmon.GetClassifier ());
	std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
        std::vector< Ptr<FlowProbe> > probes = monitor->GetAllProbes ();

	for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin ();i != stats.end (); ++i){
            // destination address, destination port, protocol, source address, source port
            Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
            difftx = i->second.timeLastTxPacket.GetSeconds() -
            i->second.timeFirstTxPacket.GetSeconds();
            //diffrx = i->second.timeLastRxPacket.GetSeconds() -
            i->second.timeFirstRxPacket.GetSeconds();
            diffrxtx = i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds();
            pdf_value = (double) i->second.rxPackets / (double) i->second.txPackets * 100;
            txbitrate_value = (double) i->second.txBytes * 8 / 1000 / difftx;
            
            if (i->second.rxPackets != 0){
                //rxbitrate_value = (double)i->second.rxPackets * m_packetSize * 8 / 1024 / diffrx;
                delay_value = (double) i->second.delaySum.GetSeconds() / (double) i->second.rxPackets;
                //throughput_value = (double)i->second.rxPackets * m_packetSize * 8 / 1024 / diffrxtx;
                throughput_value2 = (double)i->second.rxBytes * 8 / 1000 / diffrxtx;
            }
            else{
                rxbitrate_value = 0;
		delay_value = 0;
                throughput_value = 0;
                throughput_value2 = 0;
            }
		
            // We are only interested in the metrics of the data flows
            if ((!t.destinationAddress.IsSubnetDirectedBroadcast("255.255.255.0"))){
                k++;
                // Plot the statistics for each data flow
                std::cout << "\nFlow " << k << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
                std::cout << "Tx Packets: " << i->second.txPackets << "\n";
                std::cout << "Rx Packets: " << i->second.rxPackets << "\n";
                std::cout << "Lost Packets: " << i->second.lostPackets << "\n";
                std::cout << "Dropped Packets: " << i->second.packetsDropped.size() << "\n";
                std::cout << "Total Hop count: " << i->second.timesForwarded  << "\n";
                std::cout << "PDF: " << pdf_value << " %\n";
                std::cout << "Average delay: " << delay_value << "s\n";
                std::cout << "Rx bitrate: " << rxbitrate_value << " kbps\n";
                std::cout << "Tx bitrate: " << txbitrate_value << " kbps\n";
                std::cout << "Throughput: " << throughput_value << " kbps\n";
                std::cout << "Throughput2:" << throughput_value2 << " kbps\n";

                //print all nodes statistics in files              
                std::ostringstream os1;
                os1 << m_filename << "-det.txt";
                std::ofstream of1 (os1.str().c_str(), std::ios::out | std::ios::app);
                of1 << m_xSize << "x" << m_ySize << " " << m_ac << " " << m_root << " " << t.sourceAddress << " -> " << t.destinationAddress << " " << pdf_value << " " << delay_value << " " << rxbitrate_value << " " << txbitrate_value << " " << throughput_value << " " << throughput_value2 << " " << i->second.txPackets << " " << i->second.rxPackets << " " << i->second.lostPackets << " " << i->second.packetsDropped.size() << " " << m_sink << " " << m_shuffle << " " <<m_arpwait <<"\n";
                of1.close ();
                
                // Accumulate for average statistics
                totaltxPackets += i->second.txPackets;
                totaltxbytes += i->second.txBytes;
                totalrxPackets += i->second.rxPackets;
                totaldelay += i->second.delaySum.GetSeconds();
                totalrxbitrate += rxbitrate_value;
                totalrxbytes += i->second.rxBytes;
                throughput_total += throughput_value;
                throughput_total2 += throughput_value2;
            }
	}
        
	// Average all nodes statistics
	if (totaltxPackets != 0){
            pdf_total = (double) totalrxPackets / (double) totaltxPackets * 100;
	}
	else{
            pdf_total = 0;
	}
        
	if (totalrxPackets != 0){
            rxbitrate_total = totalrxbitrate;
            delay_total = (double) totaldelay / (double) totalrxPackets;
	}
	else{
            rxbitrate_total = 0;
            delay_total = 0;
	}
        
	//print all nodes statistics
	std::cout << "\nTotal PDF: " << pdf_total << " %\n";
	std::cout << "Total Rx bitrate: " << rxbitrate_total << " kbps\n";
	std::cout << "Total Delay: " << delay_total << " s\n";
        
	//print all nodes statistics in files
	std::ostringstream os;
	os << m_filename <<"-tot.txt";
	std::ofstream of (os.str().c_str(), std::ios::out | std::ios::app);
        of << m_xSize<<"x"<<m_ySize<< " " << m_conn << " " << pdf_total << " " << delay_total << " " << rxbitrate_total << " " << throughput_total << " " << throughput_total2<< " " << m_initstartLead0ToLead1 << " " << m_initstartLead0ToLead1 << " " << m_sink << " " << m_shuffle << " " << m_arpwait <<"\n";
	of.close ();
    } // end of udp printing
    else { // start of tcp printing
        // Define variables to calculate the metrics
	int k=0;
	int totaltxPackets = 0;
	int totalrxPackets = 0;
	double totaltxbytes = 0;
	double totalrxbytes = 0;
	double totaldelay = 0;
	double totalrxbitrate = 0;
        double throughput_total = 0;
        double throughput_total2 = 0;

	int totaltxPacketsAck = 0;
	int totalrxPacketsAck = 0;
	double totaltxbytesAck = 0;
	double totalrxbytesAck = 0;
	double totaldelayAck = 0;
	double totalrxbitrateAck = 0;
        double throughput_totalAck = 0;
        double throughput_total2Ack = 0;

	double difftx, /*diffrx,*/ diffrxtx;
	double pdf_value, rxbitrate_value, txbitrate_value, delay_value, throughput_value, throughput_value2;
	double pdf_total, rxbitrate_total, delay_total;
        double pdf_totalAck, rxbitrate_totalAck, delay_totalAck;

	//Print per flow statistics
	monitor->CheckForLostPackets ();
        //monitor->CheckForLostPackets(Seconds(0.001));
	Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier ());
	std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
	for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin ();i != stats.end (); ++i){
            // destination address, destination port, protocol, source address, source port
            Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first); 
            difftx = i->second.timeLastTxPacket.GetSeconds() -
            i->second.timeFirstTxPacket.GetSeconds();
            //diffrx = i->second.timeLastRxPacket.GetSeconds() -
            i->second.timeFirstRxPacket.GetSeconds();
            diffrxtx = i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds();
            pdf_value = (double) i->second.rxPackets / (double) i->second.txPackets * 100;
            txbitrate_value = (double) i->second.txBytes * 8 / 1000 / difftx;
            
            if (i->second.rxPackets != 0){
                //rxbitrate_value = (double)i->second.rxPackets * m_packetSize * 8 / 1024 / diffrx;
                delay_value = (double) i->second.delaySum.GetSeconds() / (double) i->second.rxPackets;
                //throughput_value = (double)i->second.rxPackets * m_packetSize * 8 / 1024 / diffrxtx;
                throughput_value2 = (double)i->second.rxBytes * 8 / 1000 / diffrxtx;
            }
            else{
                rxbitrate_value = 0;
                delay_value = 0;
                throughput_value = 0;
                throughput_value2 = 0;
            }
            
            // We are only interested in the metrics of the data flows
            if ((!t.destinationAddress.IsSubnetDirectedBroadcast("255.255.255.0"))){
                k++;
                // Plot the statistics for each data flow
                std::cout << "\nFlow " << k << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
                std::cout << "Tx Packets: " << i->second.txPackets << "\n";
                std::cout << "Rx Packets: " << i->second.rxPackets << "\n";
                std::cout << "Lost Packets: " << i->second.lostPackets << "\n";
                std::cout << "Dropped Packets: " << i->second.packetsDropped.size() << "\n";
                std::cout << "Total Hop count: " << i->second.timesForwarded  << "\n";
                std::cout << "PDF: " << pdf_value << " %\n";
                std::cout << "Average delay: " << delay_value << "s\n";
                std::cout << "Rx bitrate: " << rxbitrate_value << " kbps\n";
                std::cout << "Tx bitrate: " << txbitrate_value << " kbps\n";
                std::cout << "Throughput: " << throughput_value << " kbps\n";
                std::cout << "Throughput2:" << throughput_value2 << " kbps\n";
                
                if (t.sourceAddress != "10.1.1.1") {
                    //print all nodes statistics in files              
                    std::ostringstream os1;
                    os1 << m_filename << "-det.txt";
                    std::ofstream of1 (os1.str().c_str(), std::ios::out | std::ios::app);
                    of1 << m_xSize << "x" << m_ySize << " " << m_ac << " " << m_root << " " << t.sourceAddress << " -> " << t.destinationAddress << " " << pdf_value << " " << delay_value << " " << rxbitrate_value << " " << txbitrate_value << " " << throughput_value << " " << throughput_value2 << " " << i->second.txPackets << " " << i->second.rxPackets << " " << i->second.lostPackets << " " << i->second.packetsDropped.size() << " " << m_sink << " " << m_shuffle << " " << m_step << " " << m_arpwait << " \n";
                    of1.close ();

                    // Accumulate for average statistics
                    totaltxPackets += i->second.txPackets;
                    totaltxbytes += i->second.txBytes;
                    totalrxPackets += i->second.rxPackets;
                    totaldelay += i->second.delaySum.GetSeconds();
                    totalrxbitrate += rxbitrate_value;
                    totalrxbytes += i->second.rxBytes;
                    throughput_total += throughput_value;
                    throughput_total2 += throughput_value2;
                } 
                else { 
                    std::ostringstream osx1;
                    osx1 << m_filename << "-det-ack.txt";
                    std::ofstream ofx1 (osx1.str().c_str(), std::ios::out | std::ios::app);
                    ofx1 << m_xSize << "x" << m_ySize << " " << m_ac << " " << m_root << " " << t.sourceAddress << " -> " << t.destinationAddress << " " << pdf_value << " " << delay_value << " " << rxbitrate_value << " " << txbitrate_value << " " << throughput_value << " " << throughput_value2 << " " << i->second.txPackets << " " << i->second.rxPackets << " " << i->second.lostPackets << " " << i->second.packetsDropped.size() << " " << m_sink << " " << m_shuffle << " " << m_step << " " << m_arpwait <<" \n";
                    ofx1.close ();

                    // Accumulate for average statistics
                    totaltxPacketsAck += i->second.txPackets;
                    totaltxbytesAck += i->second.txBytes;
                    totalrxPacketsAck += i->second.rxPackets;
                    totaldelayAck += i->second.delaySum.GetSeconds();
                    totalrxbitrateAck += rxbitrate_value;
                    totalrxbytesAck += i->second.rxBytes;
                    throughput_totalAck += throughput_value;
                    throughput_total2Ack += throughput_value2;
                }
            }
	}
        
	// Average all nodes statistics
	if (totaltxPackets != 0){
            pdf_total = (double) totalrxPackets / (double) totaltxPackets * 100;
	}
	else{
            pdf_total = 0;
	}
        
	if (totalrxPackets != 0){
            rxbitrate_total = totalrxbitrate;
            delay_total = (double) totaldelay / (double) totalrxPackets;
	}
	else{
            rxbitrate_total = 0;
            delay_total = 0;
	}
        
        if (totaltxPacketsAck != 0){
            pdf_totalAck = (double) totalrxPacketsAck / (double) totaltxPacketsAck * 100;
	}
	else{
            pdf_totalAck = 0;
	}
        
	if (totalrxPacketsAck != 0){
            rxbitrate_totalAck = totalrxbitrateAck;
            delay_totalAck = (double) totaldelayAck / (double) totalrxPacketsAck;
	}
	else{
            rxbitrate_totalAck = 0;
            delay_totalAck = 0;
	}
        
	//print all nodes statistics
	std::cout << "\nTotal PDF: " << pdf_total << " %\n";
	std::cout << "Total Rx bitrate: " << rxbitrate_total << " kbps\n";
	std::cout << "Total Delay: " << delay_total << " s\n";
        
	//print all nodes statistics in files
	std::ostringstream os;
        os << m_filename <<"-tot.txt";
	std::ofstream of (os.str().c_str(), std::ios::out | std::ios::app);
        of << m_xSize<<"x"<<m_ySize<< " " << m_conn << " " << pdf_total << " " << delay_total << " " << rxbitrate_total << " " << throughput_total << " " << throughput_total2<< " " << m_initstartLead0ToLead1 << " " << m_initstartLead0ToLead1 << " "<< m_sink << " " << m_shuffle << " " << m_step << " " << m_arpwait <<" \n";
	of.close ();
        std::ostringstream os5;
        os5 << m_filename<<"-tot-ack.txt";
	std::ofstream of5 (os5.str().c_str(), std::ios::out | std::ios::app);
        of5 << m_xSize<<"x"<<m_ySize<< " " << m_conn << " " << pdf_totalAck << " " << delay_totalAck << " " << rxbitrate_totalAck << " " << throughput_totalAck << " " << throughput_total2Ack<< " " << m_initstartLead0ToLead1 << " " << m_initstartLead0ToLead1 << " " << m_sink << " " << m_shuffle << " " << m_step << " " << m_arpwait <<" \n";
	of5.close ();
    }
    
    Simulator::Destroy ();
    m_timeEnd=clock();
    m_timeTotal=(m_timeEnd - m_timeStart)/(double) CLOCKS_PER_SEC;
    std::cout << "\n*** Simulation time: " << m_timeTotal << "s\n\n";

    return 0;
}

void MeshTest::Report (){
    std::ostringstream osf;
    osf << m_filename << "-stat.txt";
    std::ofstream osf1 (osf.str().c_str(), std::ios::out | std::ios::app);
  
    for (NetDeviceContainer::Iterator i = meshDevices.Begin (); i != meshDevices.End (); ++i){
        Ptr<MeshPointDevice> mp = (*i)->GetObject<MeshPointDevice> ();
        Ptr<ns3::dot11s::HwmpProtocol> hwmp = mp->GetObject<ns3::dot11s::HwmpProtocol> ();
        osf1 << m_xSize<<"x"<<m_ySize<< " " << Mac48Address::ConvertFrom (mp->GetAddress ()) << " " << m_shuffle << " " << m_arpwait <<" ";
        mp->Report (osf1);
        hwmp->Report (osf1);
    }
    osf1.close ();
}

int main (int argc, char *argv[]){
    LogComponentEnable ("PacketSinkTs", LOG_LEVEL_INFO);
    LogComponentEnable ("PacketSinkTs", LOG_PREFIX_ALL); 
    LogComponentEnable ("OnOffMLM", LOG_LEVEL_ALL); 
    LogComponentEnable ("OnOffMLM", LOG_PREFIX_ALL);

    // LogComponentEnable ("FlowMonitor", LOG_LEVEL_ALL);
    // LogComponentEnable ("FlowMonitor", LOG_PREFIX_ALL);
    // LogComponentEnable ("TcpL4Protocol", LOG_LEVEL_ALL);
    // LogComponentEnable ("TcpL4Protocol", LOG_PREFIX_ALL); 
    LogComponentEnable ("TcpSocketBase", LOG_LEVEL_ALL);
    LogComponentEnable ("TcpSocketBase", LOG_PREFIX_ALL);
    LogComponentEnable ("MultipleLeadMetersScript", LOG_LEVEL_INFO);
    LogComponentEnable ("MultipleLeadMetersScript", LOG_LEVEL_ALL);

    MeshTest t; 
    t.Configure (argc, argv);
    t.Run ();
   
    return 0;
}