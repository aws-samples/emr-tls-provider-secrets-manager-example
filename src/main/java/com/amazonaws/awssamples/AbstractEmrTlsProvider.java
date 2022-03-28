/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.amazonaws.awssamples;

import com.amazonaws.retry.RetryUtils;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.AmazonEC2Exception;
import com.amazonaws.services.ec2.model.DescribeTagsRequest;
import com.amazonaws.services.ec2.model.DescribeTagsResult;
import com.amazonaws.services.ec2.model.Filter;
import com.amazonaws.services.elasticmapreduce.spi.security.TLSArtifacts;
import com.amazonaws.services.elasticmapreduce.spi.security.TLSArtifactsProvider;
import com.amazonaws.util.EC2MetadataUtils;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.function.Function;


public abstract class AbstractEmrTlsProvider extends TLSArtifactsProvider {

	protected String region;
	protected String accountId;

	protected String tlsPrivateKey;
	protected String tlsCertificate;
	protected String tlsCertificateChain;

	protected boolean initialized;

	protected static final int RETRIES=15;
	protected static final long MIN_SLEEP=1000L;
	protected static final long SLEEP_RANGE=2000L;
	protected static final Random RANDOM = new Random();

	public AbstractEmrTlsProvider() {
		initialized = false;
	}

	/**
	 * Interface to EMR TLS
	 */
	@Override
	public TLSArtifacts getTlsArtifacts() {

		init();

		//Get private key from string
		PrivateKey privateKey = getPrivateKey(this.tlsPrivateKey);

		//Get certificate from string
		List<Certificate> certChain = getX509FromString(this.tlsCertificateChain);
		List<Certificate> certs = getX509FromString(this.tlsCertificate);

		return new TLSArtifacts(privateKey,certChain,certs);
	}

	private void init(){
		if(initialized) return;

		//get account id and region under which the jar is executing
		this.accountId = EC2MetadataUtils.getInstanceInfo().getAccountId();
		this.region = EC2MetadataUtils.getInstanceInfo().getRegion();

		//read emr tags
		readTags();

		//read CA certificates
		getCertificates();

		initialized = true;

		// if you want to store certs on local disk for debug purpose
		//uncomment lines below
//		String rootPath = "/tmp/certs/";
//		String privateKeyPath = rootPath + "privateKey.pem";
//		String certificatePath = rootPath + "trustedCertificates.pem";
//		String certificateChainPath = rootPath + "certificateChain.pem";
//		createDirectoryForCerts(rootPath);
//		writeCert(privateKeyPath, this.tlsPrivateKey);
//		writeCert(certificatePath, this.tlsCertificate);
//		writeCert(certificateChainPath, this.tlsCertificateChain);
	}
	/**
	 * @Method: Create new folder
	 */
	private void createDirectoryForCerts(String folder) {
		File f = new File(folder);
		f.mkdir();
	}
	
	/**
	 * @Method: Write certificate to specified location
	 * @fileName: file location
	 * @cert: file content
	 */
	private void writeCert(String fileName, String cert) {
		
		BufferedWriter writer;
		try {
			writer = new BufferedWriter(new FileWriter(fileName));
			writer.write(cert);
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Error Writing file");
		}    
	}

	protected abstract void getCertificates();

	/**
	 * @Method: Read EMR (EC2) tags
	 */
	protected void readTags() {

		DescribeTagsRequest req = new DescribeTagsRequest();
		//get id of EC2 instance where the code is running
		String instanceId = EC2MetadataUtils.getInstanceId();

		Collection<Filter> filters = new LinkedList<>();

		List<String> instanceList = Collections.singletonList(instanceId);
		Filter filter = new Filter("resource-id", instanceList);
		filters.add(filter);
		req.setFilters(filters);

		//call AWS API to get EC2 tags
		AmazonEC2 client = AmazonEC2ClientBuilder.defaultClient();

		//Do retry when get RequestLimitExceeded
		retry(r-> {
			DescribeTagsResult tagResult=null;
			try {
				tagResult = client.describeTags(r);
				assignTags(tagResult);
			}
			catch (AmazonEC2Exception ex) {
				if (RetryUtils.isThrottlingException(ex)) {
					System.out.println("Got describeTags RequestLimitExceeded: " + ex.getMessage());
					return null;

				} else {
					System.out.println("The request failed due to: " + ex.getMessage());
					throw ex;
				}
			}
			return tagResult;
		}, req);
	}

	protected <T, R> R retry(Function<T, R> retryFunction, T input){
		R result = null;
		for(int i=0; i<RETRIES; ++i) {
			if(i>0) System.out.println(Thread.currentThread().getName()+": retry count: " + i);

			result = retryFunction.apply(input);
			if(result!=null) return result;

			randomSleep(i);
		}

		throw new RuntimeException("AbstractEmrTlsProvider retry exhausted.");
	}

	/**
	 * assign EMR (EC2) tags
	 */
	protected abstract void assignTags(DescribeTagsResult tags);

	protected void randomSleep(int i) {
		try {
			Thread.sleep(MIN_SLEEP+Math.abs(RANDOM.nextLong())%((i+1) * SLEEP_RANGE));
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	/**
	 * @Method: Convert string to correct X509 format  
	 */
	protected List<Certificate> getX509FromString(String certificateString)
	{
		List<Certificate> certs = new ArrayList<>();
		try {

			String[] lines= certificateString.split("\n");
			StringBuilder currCertSb = new StringBuilder();
			for(String line:lines){
				line = line.trim();
				if(line.equals("-----BEGIN CERTIFICATE-----")) {
					currCertSb.setLength(0);
				}
				else if(line.equals("-----END CERTIFICATE-----")){
//					System.out.println("currCertSb:"+currCertSb.toString());
					byte[] certificateData = Base64.getDecoder()
							.decode(currCertSb.toString().replaceAll("\\s+",""));

					CertificateFactory cf;
					cf = CertificateFactory.getInstance("X509");
					certs.add(cf.generateCertificate(new ByteArrayInputStream(certificateData)));
				}
				else{
					currCertSb.append(line).append("\n");
				}
			}
		} catch (CertificateException e) {
			System.out.println("error in getX509");
			e.printStackTrace();
			throw new RuntimeException(e);
		}

		return certs;

	}

	/**
	 * @Method: Convert string to correct certificate private key format  
	 */
	protected PrivateKey getPrivateKey(String pkey)
	{
		try {
			pkey = pkey.replace("-----BEGIN PRIVATE KEY-----", "");
			pkey = pkey.replace("-----END PRIVATE KEY-----", "");
			pkey = pkey.replaceAll("\\s+","");

			byte [] pkeyEncodedBytes = Base64.getDecoder().decode(pkey);

			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkeyEncodedBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");

			PrivateKey privkey = kf.generatePrivate(keySpec);

			return privkey;
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println("error in getPrivateKey");
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}
}
