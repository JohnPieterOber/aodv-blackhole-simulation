/*
  Blackhole Attack Simulation with AODV Routing Protocol
  
  Network topology is determinded by the Gauss markov mobility model  
 
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/config-store-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/applications-module.h"

// routing protocols
#include "ns3/aodv-module.h"

// header file specific to this code
#include "myapp.h"

// added for flow monitoring
#include "ns3/gnuplot.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/flow-monitor-helper.h"


// animator
#include "ns3/netanim-module.h"
//
#include <iomanip>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>

#include "sys/stat.h" 


NS_LOG_COMPONENT_DEFINE ("Blackhole");

using namespace ns3;
using namespace std;  

void ThroughputMonitor(FlowMonitorHelper *fmhelper, Ptr<FlowMonitor> monitor, Gnuplot2dDataset DataSet, Gnuplot2dDataset DataSet1, Gnuplot2dDataset DataSet2);
  

class AodvBlackholeSimulation
{

public:
  AodvBlackholeSimulation ();
  void Run ();
  void CommandSetup (int argc, char **argv);

private:
  Ptr<Socket> SetupPacketReceive (Ipv4Address addr, Ptr<Node> node, uint16_t port);
  void ReceivePacket (Ptr<Socket> socket);
  void SetupNodes();
  void SetupWith0MalicisousNodes ();
  void SetupWith2MalicisousNodes ();  
  void SetupWith5MalicisousNodes ();
  void SetupAnimationInterface();
  uint32_t m_bytesTotal;
  uint32_t m_packetsReceived;

  std::string m_phyMode;
  std::string m_rate;
  double interval;
  std::string m_rtslimit;
  int m_size;
  int m_source;
  int m_sink;
  double m_totaltime;
  int m_packetsize;
  int m_numberofpackets;
  uint16_t sinkPort;
  std::string m_protocolName;
  int m_malicioussize;
  std::string tr_name;
  std::string tr_folder_name;
  int m_simulationid;

  NodeContainer allNodes; // ALL Nodes
  NodeContainer not_malicious;
  NodeContainer malicious;
  NodeContainer detector;
};

AnimationInterface * pAnim = 0;

struct rgb {
   uint8_t r; 
   uint8_t g; 
   uint8_t b; 
 };
 
 struct rgb colors [] = {
                         { 0, 0, 0 }, // Black
                         { 255, 0, 0 }, // Red
                         { 0, 255, 0 }, // Blue
                         { 0, 0, 255 }  // Green
                         }; 

AodvBlackholeSimulation::AodvBlackholeSimulation ()
{
}

void
AodvBlackholeSimulation::SetupWith5MalicisousNodes ()
{
  m_malicioussize = 5;//Total of malicious nodes - only for logging
  allNodes.Create(m_size);

  for (int i = 0; i < m_size; i++)
  {
    if(i == 1 || i == 3 || i == 5 || i == 7 || i == 8) // malicious nodes
    {
      malicious.Add(allNodes.Get(i)); 
    }
    else if(i == 2) //detector node
    {
      detector.Add(allNodes.Get(i));
    }
    else
    {
      not_malicious.Add(allNodes.Get(i));
    }
  }
}

void
AodvBlackholeSimulation::SetupWith2MalicisousNodes ()
{
  m_malicioussize = 2;//Total of malicious nodes - only for logging
  allNodes.Create(m_size);

  for (int i = 0; i < m_size; i++)
  {
    if(i == 1 || i == 7) // malicious nodes
    {
      malicious.Add(allNodes.Get(i)); 
    }
    else if(i == 2) //detector node
    {
      detector.Add(allNodes.Get(i));
    }
    else
    {
      not_malicious.Add(allNodes.Get(i)); 
    }
  }  
}

void
AodvBlackholeSimulation::SetupWith0MalicisousNodes ()
{
  allNodes.Create(m_size);

  for (int i = 0; i < m_size; i++)
  { 
    if(i == 2) //detector node
    {
      detector.Add(allNodes.Get(i));
    }
    else
    {   
      not_malicious.Add(allNodes.Get(i));
    }
  }
}

void
AodvBlackholeSimulation::SetupAnimationInterface()
{
  pAnim = new AnimationInterface (tr_folder_name + tr_name + "blackhole_aodv_anim.xml");

  for (int i = 0; i < m_size; i++)
  {
    Ptr<Node> node = allNodes.Get (i);
    Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
    Ptr<Ipv4RoutingProtocol> proto = ipv4->GetRoutingProtocol ();
    Ptr<aodv::RoutingProtocol> aodv = DynamicCast<aodv::RoutingProtocol> (proto);
    struct rgb colorRed = colors[1];
    struct rgb colorBlue = colors[2];
    struct rgb colorGreen = colors[3];
    if (aodv)
    {
      if(aodv->GetMaliciousEnable())
      {

        pAnim->UpdateNodeDescription (node , "Malicious " + std::to_string(i));
        pAnim->UpdateNodeColor (node , colorRed.r, colorRed.g, colorRed.b); 
      }
      else if(aodv->GetDetectBlackholeEnable())
      {
        pAnim->UpdateNodeDescription (node , "DETECTOR " + std::to_string(i));
        pAnim->UpdateNodeColor (node , colorBlue.r, colorBlue.g, colorBlue.b); 
      }
      else
      {
        pAnim->UpdateNodeColor (node , colorGreen.r, colorGreen.g, colorGreen.b); 
      }    
    }
  }
  
  pAnim->EnablePacketMetadata (true);  
}

void
AodvBlackholeSimulation::CommandSetup (int argc, char **argv)
{
  CommandLine cmd;
  cmd.AddValue ("size", "The number of nodes", m_size);
  //cmd.AddValue ("source", "The node number of the source", m_source);
  //cmd.AddValue ("sink", "The node number of the sink", m_sink);
  //cmd.AddValue ("rtslimit", "RTS/CTS threshold in bytes", m_rtslimit);
  cmd.AddValue ("phyMode", "Wifi Phy mode", m_phyMode);
  cmd.AddValue ("totaltime", "The simulation time", m_totaltime);
  cmd.AddValue ("packetsize", "The packet size", m_packetsize);  
  cmd.AddValue ("numberofpackets", "The number of packets", m_numberofpackets);
  cmd.AddValue ("rate", "The rate", m_rate);
  cmd.AddValue ("maliciousnodes", "The number of malicious nodes",m_malicioussize);
  cmd.AddValue ("simulationid", "The simulation id", m_simulationid);
  cmd.Parse (argc, argv);
}

int
main (int argc, char *argv[])
{
  AodvBlackholeSimulation simulation;
  simulation.CommandSetup (argc, argv);
  simulation.Run ();
}

void 
AodvBlackholeSimulation::SetupNodes()
{
  if(m_malicioussize == 0)
  {
    SetupWith0MalicisousNodes();
    return;
  }

  if(m_malicioussize == 2)
  {
    SetupWith2MalicisousNodes();
    return;
  }

  if(m_malicioussize == 5)
  {
    SetupWith5MalicisousNodes();
    return;
  }
}

void
AodvBlackholeSimulation::Run ()
{
  
  interval = 0.015; //seconds
  m_rtslimit = "1500";//bytes
  m_source = 0; //ip = 10.1.1.1 : when updating this parameter also update the thresold check IP source and destination adressess
  m_sink = 9; //ip = 10.1.1.10 : when updating this parameter also update the thresold check IP source and destination adressess
  m_protocolName = "ADOV";
  uint16_t sinkPort = 6;

  //From command line
  //m_phyMode = "DsssRate11Mbps";//IEEE 802.11b  
  //m_size = 20;//Total of all nodes  
  //m_rate = "2048Kbps";
  //m_totaltime = 100.0;
  //m_packetsize = 64;
  //m_numberofpackets = 100;

  
    // Convert to time object
  Time interPacketInterval = Seconds (interval);
  // turn off RTS/CTS for frames below 2200 bytes
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue (m_rtslimit));
  // Fix non-unicast data rate to be the same as that of unicast
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue (m_phyMode));

  //create malicious nodes and legitimate nodes
  NS_LOG_INFO ("Create nodes.");  
  SetupNodes();

  NS_LOG_INFO ("Define log file name and folder");
  // Creating a directory 
  tr_folder_name = "aodv_blackhole_experiment_output_" + std::to_string(m_simulationid) + "/";
  mkdir(tr_folder_name.c_str(), 0777);
  tr_name = "";//tr_folder_name + m_protocolName + "_simulationid" + std::to_string(m_simulationid) + "_";//+ "_" + std::to_string(m_size) + "nodes_" + std::to_string(m_malicioussize) + "maliciousnodes_" + std::to_string(m_numberofpackets) + "packets_" + std::to_string(m_packetsize) + "packetsize_" + m_rate;

  // Set up WiFi
  WifiHelper wifi;

  YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
  wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11);

  YansWifiChannelHelper wifiChannel ;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::TwoRayGroundPropagationLossModel",
                                  "SystemLoss", DoubleValue(1),
                                "HeightAboveZ", DoubleValue(1.5));
  //For range near 250m
   wifiPhy.Set ("TxPowerStart", DoubleValue(33));
   wifiPhy.Set ("TxPowerEnd", DoubleValue(33));
   wifiPhy.Set ("TxPowerLevels", UintegerValue(1));
   wifiPhy.Set ("TxGain", DoubleValue(0));
   wifiPhy.Set ("RxGain", DoubleValue(0));
   wifiPhy.Set ("EnergyDetectionThreshold", DoubleValue(-61.8));//The energy of a received signal should be higher than this threshold (dbm) to allow the PHY layer to detect the signal.
   wifiPhy.Set ("CcaMode1Threshold", DoubleValue(-64.8));


  wifiPhy.SetChannel (wifiChannel.Create ());

  // Add a MAC
  WifiMacHelper wifiMac;
  wifiMac.SetType ("ns3::AdhocWifiMac");

  // Set 802.11b standard and disable the rate control
  wifi.SetStandard (WIFI_PHY_STANDARD_80211b);

  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                "DataMode",StringValue(m_phyMode),
                                "ControlMode",StringValue(m_phyMode));


  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, allNodes);
  //Create pcap file to capture packets
  //wifiPhy.EnablePcapAll(std::string("aodv")); //Disable for this project

  // Enable AODV and blackhole attack
  AodvHelper aodv;
  AodvHelper malicious_aodv;
  AodvHelper detector_aodv;

  // turn off hello transmissions that confuse the logs
  aodv.Set("EnableHello", BooleanValue (false));
  malicious_aodv.Set("EnableHello", BooleanValue (false));
  detector_aodv.Set("EnableHello", BooleanValue (false));

  // Set up Internet stack
  InternetStackHelper internet;
  internet.SetRoutingHelper (aodv);
  internet.Install (not_malicious);
  
  malicious_aodv.Set("IsMalicious",BooleanValue(true)); // putting *false* instead of *true* would disable the malicious behavior of the node
  internet.SetRoutingHelper (malicious_aodv);
  internet.Install (malicious);

   // set detector node
  detector_aodv.Set("IsDetectBlackhole", BooleanValue(true));
  internet.SetRoutingHelper (detector_aodv);
  internet.Install (detector);

  // Set up Addresses
  Ipv4AddressHelper ipv4;
  NS_LOG_INFO ("Assign IP Addresses.");
  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer ifcont = ipv4.Assign (devices);

  //Set Mobility for all nodes
  MobilityHelper mobility;
  mobility.SetMobilityModel ("ns3::GaussMarkovMobilityModel",
    "Bounds", BoxValue (Box (0, 3000, 0, 3000, 0, 300)),
    "TimeStep", TimeValue (Seconds (0.5)),
    "Alpha", DoubleValue (0.85),
    "MeanVelocity", StringValue ("ns3::UniformRandomVariable[Min=800|Max=1200]"),
    "MeanDirection", StringValue ("ns3::UniformRandomVariable[Min=0|Max=6.283185307]"),
    "MeanPitch", StringValue ("ns3::UniformRandomVariable[Min=0.05|Max=0.05]"),
    "NormalVelocity", StringValue ("ns3::NormalRandomVariable[Mean=0.0|Variance=0.0|Bound=0.0]"),
    "NormalDirection", StringValue ("ns3::NormalRandomVariable[Mean=0.0|Variance=0.2|Bound=0.4]"),
    "NormalPitch", StringValue ("ns3::NormalRandomVariable[Mean=0.0|Variance=0.02|Bound=0.04]"));
  mobility.SetPositionAllocator ("ns3::RandomBoxPositionAllocator",
    "X", StringValue ("ns3::UniformRandomVariable[Min=0|Max=1500]"),
    "Y", StringValue ("ns3::UniformRandomVariable[Min=0|Max=1500]"),
    "Z", StringValue ("ns3::UniformRandomVariable[Min=0|Max=100]"));
  mobility.Install (allNodes);


  NS_LOG_INFO ("Create Applications.");
  Config::SetDefault  ("ns3::OnOffApplication::PacketSize",StringValue ("64"));
  Config::SetDefault ("ns3::OnOffApplication::DataRate",  StringValue (m_rate));
  OnOffHelper onoff1 ("ns3::UdpSocketFactory",Address ());
  onoff1.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1.0]"));
  onoff1.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0.0]"));
  std::ostringstream oss;
  oss << "Sink : "; 
  ifcont.GetAddress (m_sink).Print(oss);
  NS_LOG_UNCOND(oss.str ());

  Ptr<Socket> sink = SetupPacketReceive (ifcont.GetAddress (m_sink), allNodes.Get (m_sink), sinkPort);
  AddressValue remoteAddress (InetSocketAddress (ifcont.GetAddress (m_sink), sinkPort));
  onoff1.SetAttribute ("Remote", remoteAddress);

  Ptr<UniformRandomVariable> var = CreateObject<UniformRandomVariable> ();
  ApplicationContainer temp = onoff1.Install (allNodes.Get (0));
  temp.Start (Seconds (var->GetValue (30.0,31.0)));
  temp.Stop (Seconds (m_totaltime));

  // Create file for throughput performance
  // used for create gnuplot file to show performance figure of Throughput
  std::string fileName = tr_folder_name + tr_name + "throughput" ;
  std::string graphic = "throughput.png";
  std::string plotfilename = fileName + ".plt";
  std::string plottitle = "Throughput";
  std::string datatitle = "Throughput";

  Gnuplot gnuplot (graphic);
  gnuplot.SetTitle (plottitle);
  gnuplot.SetTerminal("png");
  gnuplot.SetLegend("Simulation time in seconds", "Throughput");//set labels for each axis
  Gnuplot2dDataset dataset;
  dataset.SetTitle (datatitle);
  dataset.SetStyle (Gnuplot2dDataset::LINES_POINTS);

//used for create gnuplot file to show performance figure of Packet loss
  std::string fileName1 =  tr_folder_name + tr_name + "packetloss";
  std::string graphic1 = "packetloss.png";
  std::string plotfilename1 = fileName1 + ".plt";
  std::string plottitle1 = "Packetloss";
  std::string datatitle1 = "Packetloss";

  Gnuplot gnuplot1 (graphic1);
  gnuplot1.SetTitle (plottitle1);
  gnuplot1.SetTerminal("png");
  gnuplot1.SetLegend("Simulation time in seconds", "Number of packet loss");//set labels for each axis
  Gnuplot2dDataset dataset1;
  dataset1.SetTitle (datatitle1);
  dataset1.SetStyle (Gnuplot2dDataset::LINES_POINTS);

//used for create gnuplot file to show performance figure of end-to-end delay
  std::string fileName2 = tr_folder_name + tr_name + "delay";
  std::string graphic2 = "delay.png";
  std::string plotfilename2 = fileName2 + ".plt";
  std::string plottitle2 = "End-to-End delay";
  std::string datatitle2 = "End-to-End delay";

  Gnuplot gnuplot2 (graphic2);
  gnuplot2.SetTitle (plottitle2);
  gnuplot2.SetTerminal("png");
  gnuplot2.SetLegend("Simulation time in seconds", "Average End-to-End delay for each flow(ns)");//set labels for each axis
  Gnuplot2dDataset dataset2;
  dataset2.SetTitle (datatitle2);
  dataset2.SetStyle (Gnuplot2dDataset::LINES_POINTS);

  //print routing table
  Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> (tr_folder_name + tr_name + "blackhole.routes", std::ios::out);
  aodv.PrintRoutingTableAllAt (Seconds (m_totaltime + 1), routingStream);

  NS_LOG_INFO ("Configure Tracing.");
  AsciiTraceHelper ascii;
  MobilityHelper::EnableAsciiAll (ascii.CreateFileStream (tr_folder_name + tr_name + "blackhole.mob"));

  // install Flowmonitor on all nodes
  FlowMonitorHelper fmHelper;
  Ptr<FlowMonitor> flow = fmHelper.InstallAll();

  ThroughputMonitor(&fmHelper,flow,dataset,dataset1,dataset2);
  
  // do the actual simulation.
  SetupAnimationInterface();
  NS_LOG_INFO ("Run Simulation.");  
  Simulator::Stop (Seconds(m_totaltime));
  Simulator::Run ();

  flow->CheckForLostPackets ();

  //add the Throughput dataset to the plot
    gnuplot.AddDataset(dataset);
  // Open the plot file.
    std::ofstream plotFile (plotfilename.c_str());
  // Write the plot file.
    gnuplot.GenerateOutput (plotFile);
  // Close the plot file.
    plotFile.close ();

  //add the Packet loss dataset to the plot
    gnuplot1.AddDataset(dataset1);
  // Open the plot file.
    std::ofstream plotFile1 (plotfilename1.c_str());
  // Write the plot file.
    gnuplot1.GenerateOutput (plotFile1);
  // Close the plot file.
    plotFile1.close ();

  //add the end-to-end delay dataset to the plot
    gnuplot2.AddDataset(dataset2);
  // Open the plot file.
    std::ofstream plotFile2 (plotfilename2.c_str());
  // Write the plot file.
    gnuplot2.GenerateOutput (plotFile2);
  // Close the plot file.
    plotFile2.close ();

  flow->SerializeToXmlFile(tr_folder_name + tr_name + "blackhole.flow", true, true);

  Simulator::Destroy();
}

Ptr<Socket> 
AodvBlackholeSimulation::SetupPacketReceive (Ipv4Address addr, Ptr<Node> node, uint16_t port)
{
  NS_LOG_INFO ("Setup event for packets received.");

  TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
  Ptr<Socket> sink = Socket::CreateSocket (node, tid);
  InetSocketAddress local = InetSocketAddress (addr, port);
  sink->Bind (local);
  sink->SetRecvCallback (MakeCallback (&AodvBlackholeSimulation::ReceivePacket, this));

  return sink;
}

static inline std::string
PrintReceivedPacket (Ptr<Socket> socket, Ptr<Packet> packet, Address senderAddress)
{
  std::ostringstream oss;

  oss << Simulator::Now ().GetSeconds () << " " << socket->GetNode ()->GetId ();

  if (InetSocketAddress::IsMatchingType (senderAddress))
    {
      InetSocketAddress addr = InetSocketAddress::ConvertFrom (senderAddress);
      oss << " received one packet from " << addr.GetIpv4 ();
    }
  else
    {
      oss << " received one packet!";
    }
  return oss.str ();
}

void 
AodvBlackholeSimulation::ReceivePacket (Ptr<Socket> socket)
{
  Ptr<Packet> packet;
  Address senderAddress;
  while ((packet = socket->RecvFrom (senderAddress)))
    {
      m_bytesTotal += packet->GetSize ();
      m_packetsReceived += 1;
      NS_LOG_UNCOND (PrintReceivedPacket (socket, packet, senderAddress));
    }
}

void 
ThroughputMonitor(FlowMonitorHelper *fmhelper, Ptr<FlowMonitor> monitor, Gnuplot2dDataset DataSet, Gnuplot2dDataset DataSet1, Gnuplot2dDataset DataSet2)
{
  double Throughput = 0;
  double packetloss = 0;
  double delay = 0;

  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (fmhelper->GetClassifier ());
  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
    {
      Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
      if(t.sourceAddress==Ipv4Address("10.1.1.1")&&t.destinationAddress==Ipv4Address("10.1.1.10"))
      {
        std::cout << "Flow ID:    " << i->first  << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
        std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";        
        std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
        std::cout <<"Duration   : "<<(i->second.timeLastRxPacket.GetSeconds()-i->second.timeFirstTxPacket.GetSeconds())<<std::endl;
        std::cout <<"Last Received Packet : "<< i->second.timeLastRxPacket.GetSeconds()<<" Seconds"<<std::endl;
        std::cout <<"Throughput: " << i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds())/1024/1024  << " Mbps\n";
        std::cout <<"Average delay: "<< (i->second.delaySum.GetSeconds()/i->second.rxPackets)<<std::endl;
        std::cout <<"Packet drop: "<<i->second.lostPackets<<"\n";
        std::cout<<"---------------------------------------------------------------------------"<<std::endl;
        
        Throughput = (i->second.rxBytes * 8.0 / (i->second.timeLastRxPacket.GetSeconds()-i->second.timeFirstTxPacket.GetSeconds())/1024/1024  );
        packetloss = (i->second.lostPackets);
        delay = (i->second.delaySum.GetDouble()/i->second.rxPackets);
        //update gnuplot file data
        DataSet.Add((double)Simulator::Now().GetSeconds(), (double) Throughput);
        DataSet1.Add((double)Simulator::Now().GetSeconds(), (double) packetloss);
        DataSet2.Add((double)Simulator::Now().GetSeconds(), (double) delay);
      }
    }
    
  Simulator::Schedule(Seconds(1),&ThroughputMonitor, fmhelper, monitor, DataSet, DataSet1, DataSet2);
}