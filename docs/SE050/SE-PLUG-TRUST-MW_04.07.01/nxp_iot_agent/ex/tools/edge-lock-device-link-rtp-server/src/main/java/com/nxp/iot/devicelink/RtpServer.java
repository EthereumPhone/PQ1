/*
 * Copyright 2020-2021,2024-2025 NXP.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.nxp.iot.devicelink;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nxp.iot.devicelink.EcCurveParams.ECCurve;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.io.FilenameFilter;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.lang.invoke.MethodHandles;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Command(name = "rtpServer", mixinStandardHelpOptions = true, version = "RTP Server v1.9.0",
		description = "EdgeLock2Go Remote Provisioning Server."
				+ "Starts server on requested port and provisions client device with provisionings "
				+ "read from JSON files found in requested directory.")
public class RtpServer implements Runnable {

	@Option(names = {"-d", "--dir"}, description = "The directory containing JSON files downloaded from EL2GO. "
			+ "Default value: c:\\temp", defaultValue = "c:\\temp")
	private static String rtpJsonFileDir = "c:\\temp";

	@Option(names = {"-p", "--port"}, description = "The port on which server needs to be started. "
			+ "Default value: 7050", defaultValue = "7050")
	private int port = 7050;

	@Option(names = {"-o", "--optimize"}, description = "Optimize search of provisionings in JSON files by considering only files "
			+ "where the ID of the connecting device (in decimal format) is present in it file name. Default value: false",
			defaultValue = "false")
	private static boolean optimizeSearchForDeviceID = false;

	@Option(names = {"-f", "--force-curve-install"}, description = "Force curve and its parameter installation even if is already"
			+ "installed on device. In this case the response status word check of the CreateECCurve/SetECCurveParam APDUs will be skipped."
			+ "Default value: false",
			defaultValue = "false")
	private static boolean forceCurveInstallation = false;

	private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	private static final int DATA_READ_TIMEOUT_MILLIS = 20000;

	private Socket server;
	private byte major;
	private byte minor;
	private byte patch;
	private byte[] installedCurves = new byte[18];

	private List<Integer> provisionedIds;
	private List<Integer> failedProvisionedIds;

	private static boolean isTestRun = false;

	public List<Integer> getProvisionedIds() {
		return provisionedIds;
	}

	public List<Integer> getFailedProvisionedIds() {
		return failedProvisionedIds;
	}

	public static void setIsTestRun(boolean isTestRun) {
		RtpServer.isTestRun = isTestRun;
	}

	public static void setRtpJsonFileDir(String rtpJsonFileDir) {
		RtpServer.rtpJsonFileDir = rtpJsonFileDir;
	}

	public static void setOptimizeSearchForDeviceID(boolean optimizeSearchForDeviceID) {
		RtpServer.optimizeSearchForDeviceID = optimizeSearchForDeviceID;
	}

	public static void setForceCurveInstallation(boolean forceCurveInstallation) {
		RtpServer.forceCurveInstallation = forceCurveInstallation;
	}

	/**
	 * This enum identifies the values of the Tag type.
	 */
	public enum Tag {
		START_CLIENT((short) 0),
		APDU_CMD((short) 0x8000),
		APDU_RESPONSE((short) 0x8100),
		PROVISIONED_OBJECTS_LIST((short) 0x8200),
		PROVISIONED_OBJECTS_LIST_RESPONSE((short) 0x8300),
		FAILED_PROVISIONED_LIST((short) 0x8400),
		FAILED_PROVISIONED_LIST_RESPONSE((short) 0x8500),
		DONE((short) 0xFF00);

		public final short value;

		Tag(short value) {
			this.value = value;
		}
	}

	/**
	 * Foo.
	 */
	public static void main(String... args) {
		int exitCode = new CommandLine(new RtpServer()).execute(args);
		System.exit(exitCode);
	}

	@Override
	public void run() {
		try (ServerSocket serverSocket = new ServerSocket(port);) {
			while (true) {
				LOGGER.info(String.format("---Provisioning server is listening on port %d for new client connection---", port));
				server = serverSocket.accept();
				try {
					LOGGER.info(String.format("---Provisioning client connected on port %d---", port));
					provisionedIds = new ArrayList<>();
					failedProvisionedIds = new ArrayList<>();
					startClient();
					BigInteger deviceId = getDeviceId();
					LOGGER.info(String.format("New client connected with deviceID: [%d]", deviceId));
					getVersion();
					List<Integer> idList = getIdList();
					readInstalledCurveList();
					provisionDevice(deviceId, idList);
					processResult();
					sendGoodBye();
				} catch (ProtocolException e) {
					LOGGER.error("Protocol Failure. Aborting provisioning", e);
				} catch (SocketTimeoutException e) {
					LOGGER.error("Socket timeout while reading data from client: Aborting provisioning");
				} catch (IOException e) {
					LOGGER.error(String.format("%s. Error in communication with client", e.getMessage()));
				}  finally {
					server.close();
				}
			}
		} catch (IOException e) {
			LOGGER.error(String.format("%s. IO Failure Shutting down server", e.getMessage()));
		}
	}

	private void startClient() throws IOException {
		sendCmd(Tag.START_CLIENT);
		if (getResponse().cmd != Tag.START_CLIENT.value) {
			throw new ProtocolException("Protocol Error: Unexpected Tag in startClient response");
		}
	}

	private BigInteger getDeviceId() throws IOException {
		sendCmd(Tag.APDU_CMD, ApduContainer.GET_UUID_APDU, server.getOutputStream());
		TlvFrame uidResponse = getResponse();
		if (uidResponse.cmd != Tag.APDU_RESPONSE.value) {
			throw new ProtocolException("Protocol Error: Unexpected Tag in getDeviceId response");
		}
		try {
			BigInteger deviceId = new BigInteger(Utils.trimByteArray(uidResponse.payload, 4, ApduContainer.DEVICE_ID_LENGTH_BYTES));
			LOGGER.debug(String.format("DeviceID: Hex[%016X]", deviceId));
			return deviceId;
		} catch (IllegalArgumentException e) {
			throw new ProtocolException("Unable to retrieve DeviceID");
		}
	}

	private void getVersion() throws IOException {
		sendCmd(Tag.APDU_CMD, ApduContainer.GET_VERSION_APDU, server.getOutputStream());
		TlvFrame versionInfoResponse = getResponse();
		if (versionInfoResponse.cmd != Tag.APDU_RESPONSE.value) {
			throw new ProtocolException("Protocol Error: Unexpected Tag in getVersion response");
		}
		try {
			byte[] versionInfo = Utils.trimByteArray(versionInfoResponse.payload, 4, ApduContainer.VERSION_INFO_LENGTH_BYTES);
			major = versionInfo[0];
			minor = versionInfo[1];
			patch = versionInfo[2];
			LOGGER.info(String.format("major: [%02X], minor: [%02X], patch: [%02X]", major, minor, patch));
		} catch (IllegalArgumentException e) {
			throw new ProtocolException("Unable to retrieve applet version");
		}
	}

	private byte[] readInstalledCurveList() throws IOException {
		sendCmd(Tag.APDU_CMD, ApduContainer.GET_CURVE_LIST_APDU, server.getOutputStream());
		TlvFrame curveListResponse = getResponse();
		if (curveListResponse.cmd != Tag.APDU_RESPONSE.value) {
			throw new ProtocolException("Protocol Error: Unexpected Tag in readInstalledCurveList response");
		}
		try {
			byte[] curveList = Utils.trimByteArray(curveListResponse.payload, 4, ApduContainer.CURVE_LIST_LENGTH_BYTES);
			LOGGER.debug(String.format("CurveList: %s", Utils.byteArrayToHexString(curveList)));
			System.arraycopy(curveList, 0, installedCurves, 1, ApduContainer.CURVE_LIST_LENGTH_BYTES);
			return curveList;
		} catch (IllegalArgumentException e) {
			throw new ProtocolException("Unable to read CurveList");
		}
	}

	private List<Integer> getIdList() throws IOException {
		sendCmd(Tag.APDU_CMD, ApduContainer.GET_ID_LIST_APDU, server.getOutputStream());
		TlvFrame idListResponse = getResponse();
		if (idListResponse.cmd != Tag.APDU_RESPONSE.value) {
			throw new ProtocolException("Protocol Error: Unexpected Tag in getIdList response");
		}
		try {
			byte[] idsRaw = Utils.trimByteArray(idListResponse.payload, 7, idListResponse.payload.length - 7 - 2);
			int numberOfIds = idsRaw.length / 4;
			List<Integer> idList = new ArrayList<>();
			for (int i = 0; i < numberOfIds; i++) {
				idList.add(Utils.getInt(idsRaw, i * 4));
			}

			LOGGER.info(String.format("READ ID LIST -  objectIds: {%s}",
					Arrays.stream(idList.stream()
							.mapToInt(Integer::intValue)
							.toArray()).mapToObj(o -> String.format("0x%08x", o))
							.collect(Collectors.joining(", "))));
			return idList;
		} catch (Exception e) {
			throw new ProtocolException("Unable to read ID List");
		}
	}

	private void provisionDevice(BigInteger deviceId, List<Integer> idList) throws IOException {
		LOGGER.info(String.format("Reading provisionings from directory from %s", rtpJsonFileDir));
		File dir = new File(rtpJsonFileDir);

		File[] directoryListing;
		if (optimizeSearchForDeviceID) {
			directoryListing = dir.listFiles(new FilenameFilter() {
				@Override
				public boolean accept(File dir, String name) {
					if (name.endsWith(".json")) {
						return name.contains(String.valueOf(deviceId));
					}
					return false;
					}
			});
		}
		else {
			directoryListing = dir.listFiles((dirs, name) -> name.toLowerCase().endsWith(".json"));
		}

		if (directoryListing != null && directoryListing.length > 0) {
			for (File child : directoryListing) {
				List<JsonProvisioning> records;
				try (FileReader is = new FileReader(child.getAbsoluteFile().toString())) {
					ObjectMapper mapper = new ObjectMapper();
					records = mapper.readValue(is, new TypeReference<List<JsonProvisioning>>() {
					});
					if (records == null) {
						throw new Exception("Mapped records returned null");
					}
				} catch (Exception e) {
					throw new IOException("Json File has invalid format.", e);
				}
				JsonProvisioning[] provisionings = records.stream()
						.filter(r -> r.deviceId.equals(String.valueOf(deviceId)))
						.toArray(JsonProvisioning[]::new);

				if (provisionings.length == 0) {
					LOGGER.info(String.format("found zero provisionings for device %d in file %s", deviceId, child.toString()));
				}

				for (JsonProvisioning deviceProvisioning : provisionings) {
					LOGGER.info(String.format("found %d provisionings for device %d in file %s",
							deviceProvisioning.getRtpProvisionings().size(), deviceId, child.toString()));
					for (JsonProvisioning.RtpDeviceProvisioning rtpProvisionings : deviceProvisioning.getRtpProvisionings()) {
						int objectId = (int) Long.parseLong(rtpProvisionings.secureObject.objectId, 16);
						switch (rtpProvisionings.state) {
							case "GENERATION_COMPLETED":
								break;
							case "PROVISIONING_COMPLETED":
								LOGGER.info(String.format("Provisioning state of object at [0x%08x] is already completed. Skipping provisioning", objectId));
								continue;
							default:
								LOGGER.warn(String.format("Provisioning state of object at [0x%08x] is %s. Verify input file!", objectId, rtpProvisionings.state));
								continue;
						}
						try {
							if (idList.contains(objectId)) {
								LOGGER.info(String.format("Found existing object [0x%08x]. Needs to be deleted.", objectId));
								deleteObject(objectId);
								LOGGER.info(String.format("Deleted object [0x%08x], Now provisioning", objectId));
							}

							installEcCurveIfNecessary(rtpProvisionings);

							if (rtpProvisionings.apdus.createApdu != null && rtpProvisionings.apdus.createApdu.apdu != null) {
								processProvisionApdu(rtpProvisionings.apdus.createApdu.apdu);

								if (rtpProvisionings.apdus.writeApdus != null) {
									for (JsonProvisioning.Apdu writeApdus : rtpProvisionings.apdus.getWriteApdus()) {
										processProvisionApdu(writeApdus.apdu);
									}
								}
								provisionedIds.add(objectId);
								LOGGER.info(String.format("Successfully provisioned object [0x%08x]", objectId));
							} else {
								throw new UnsupportedEncodingException("APDUs for creating secure object are missing.");
							}
						} catch (UnsupportedEncodingException | IllegalArgumentException e) {
							failedProvisionedIds.add(objectId);
							LOGGER.error(String.format("%s. Unable to provision object at [0x%08x]. Skipping provisioning: ", e.getMessage(), objectId));
						}
					}
				}
			}
		} else {
			LOGGER.warn(String.format("No provisionings found for the connecting device inside the directory [%s].", rtpJsonFileDir));
		}
	}

	private boolean isECMontCurveInstallationRequired() {
		return major >= 5;
	}

	private void installEcCurveIfNecessary(JsonProvisioning.RtpDeviceProvisioning rtpProvisionings) throws IOException {
		String algorithm = rtpProvisionings.secureObject.algorithm;
		if (isTestRun) {
			algorithm = rtpProvisionings.secureObject.name;
		}

		if ((rtpProvisionings.secureObject.type.equals("KEYPAIR") || rtpProvisionings.secureObject.type.equals("STATIC_PUBLIC_KEY"))
				&& algorithm != null && EcCurveParams.isEcKeyPair(algorithm)) {
			// in case the force curve installation option is provided, the curve and parameters needs to be always installed
			// and the returned status word check will be skipped
			if ((!getInstalledEcCurveStatus(EcCurveParams.getEcCurveIndex(algorithm))) || (forceCurveInstallation)) {
				for (String apdu : EcCurveParams.getInstallEcCurveAPdus(algorithm)) {
					processProvisionApdu(Utils.hexStringToByteArray(apdu), forceCurveInstallation);
					setInstalledEcCurveStatus(EcCurveParams.getEcCurveIndex(algorithm).value);
				}
			}
		}
	}

	private boolean getInstalledEcCurveStatus(ECCurve curve) {
		switch (curve) {
			case ID_ECC_ED_25519:
				return false;
			case ID_ECC_MONT_DH_25519:
			case ID_ECC_MONT_DH_448:
				return !isECMontCurveInstallationRequired();
			default:
				return (installedCurves[curve.value] == 0x02);
		}
	}

	private void setInstalledEcCurveStatus(int curveIndex) {
		if (curveIndex < 0x40) {
			installedCurves[curveIndex] = 0x02;
		}
	}

	private void processProvisionApdu(byte[] apdu) throws IOException {
		sendCmd(Tag.APDU_CMD, apdu, server.getOutputStream());
		TlvFrame apduResponse = getResponse();
		String response = Utils.byteArrayToHexString(apduResponse.payload);
		if (apduResponse.cmd != Tag.APDU_RESPONSE.value || !response.endsWith("9000")) {
			throw new InvalidParameterException(String.format("Unexpected response: [%s].", response));
		}
	}

	private void processProvisionApdu(byte[] apdu, boolean skipStatusWordCheck) throws IOException {
		sendCmd(Tag.APDU_CMD, apdu, server.getOutputStream());
		TlvFrame apduResponse = getResponse();
		String response = Utils.byteArrayToHexString(apduResponse.payload);
		if ((apduResponse.cmd != Tag.APDU_RESPONSE.value || !response.endsWith("9000")) && !skipStatusWordCheck) {
			throw new InvalidParameterException(String.format("Unexpected response: [%s].", response));
		}
	}

	private void deleteObject(int objectId) throws IOException {
		sendCmd(Tag.APDU_CMD, Utils.concat(ApduContainer.GET_DELETE_OBJECT_APDU, ByteBuffer.allocate(4).putInt(objectId).array()),
				server.getOutputStream());
		TlvFrame apduResponse = getResponse();
		String response = Utils.byteArrayToHexString(apduResponse.payload);
		if (apduResponse.cmd != Tag.APDU_RESPONSE.value || !response.equals("9000")) {
			throw new InvalidParameterException(String.format("Delete objectId [0x%08x] failed with [%s]", objectId, response));
		}
	}

	private void sendCmd(Tag cmd) throws IOException {
		sendCmd(cmd, new byte[0], server.getOutputStream());
	}

	/**
	 * This function creates and sends Tlv frame to be sent over TCP.
	 */
	public static void sendCmd(Tag cmd, byte[] apdu, OutputStream outputStream) throws IOException {
		int len = apdu.length;
		byte[] cmdByte = ByteBuffer.allocate(2).putShort(cmd.value).array();
		byte[] lenByte = ByteBuffer.allocate(2).putShort((short) len).array();
		outputStream.write(Utils.concat(cmdByte, lenByte, apdu));
	}

	private TlvFrame getResponse() throws IOException {
		server.setSoTimeout(DATA_READ_TIMEOUT_MILLIS);
		return getResponse(server.getInputStream());
	}

	/**
	 * This function returns a Tlv frame from data read over TCP.
	 */
	public static TlvFrame getResponse(InputStream inStream) throws IOException {
		byte[] cmdAndLen = new byte[4];
		int readBytesLen = inStream.read(cmdAndLen);
		if (readBytesLen != cmdAndLen.length) {
			throw new IOException("Unexpected number of bytes received");
		}
		TlvFrame response = new TlvFrame();
		response.cmd = (short) (((cmdAndLen[0] & 0xFF) << 8) | (cmdAndLen[1] & 0xFF));
		response.length = (short) (((cmdAndLen[2] & 0xFF) << 8) | (cmdAndLen[3] & 0xFF));
		if (response.length != 0) {
			byte[] payload = new byte[response.length];
			readBytesLen = inStream.read(payload);
			if (readBytesLen != response.length) {
				throw new IOException("Unexpected number of bytes received");
			}
			response.payload = payload;
		}
		return response;
	}

	private void processResult() throws IOException {
		if (!provisionedIds.isEmpty()) {
			LOGGER.info(String.format("Provisioned objects -  objectIds: {%s}",
					Arrays.stream(provisionedIds.stream()
							.mapToInt(Integer::intValue)
							.toArray()).mapToObj(o -> String.format("0x%08x", o))
							.collect(Collectors.joining(", "))));
			byte[] provisionedIdsBytes = Utils.intArrayToByteArray(provisionedIds.stream().mapToInt(Integer::intValue).toArray());
			sendCmd(Tag.PROVISIONED_OBJECTS_LIST, provisionedIdsBytes, server.getOutputStream());
			TlvFrame processResult = getResponse();
			if (processResult.cmd != Tag.PROVISIONED_OBJECTS_LIST_RESPONSE.value) {
				throw new ProtocolException("Protocol Error: Unexpected Tag in provisionedObjectList response");
			}
		}
		if (!failedProvisionedIds.isEmpty()) {
			LOGGER.info(String.format("Unsuccessful provisionings -  objectIds: {%s}",
					Arrays.stream(failedProvisionedIds.stream()
							.mapToInt(Integer::intValue)
							.toArray()).mapToObj(o -> String.format("0x%08x", o))
							.collect(Collectors.joining(", "))));
			byte[] failedIdsByteArray = Utils.intArrayToByteArray(failedProvisionedIds.stream().mapToInt(Integer::intValue).toArray());
			sendCmd(Tag.FAILED_PROVISIONED_LIST, failedIdsByteArray, server.getOutputStream());
			TlvFrame processResult = getResponse();
			if (processResult.cmd != Tag.FAILED_PROVISIONED_LIST_RESPONSE.value) {
				throw new ProtocolException("Protocol Error: Unexpected Tag in failedProvisionedObjectList response");
			}
		}
	}

	private void sendGoodBye() throws IOException {
		sendCmd(Tag.DONE);
	}
}
