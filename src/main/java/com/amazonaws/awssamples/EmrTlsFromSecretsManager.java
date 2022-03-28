/**
 * MIT No Attribution
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.amazonaws.awssamples;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.retry.RetryUtils;
import com.amazonaws.services.certificatemanager.model.AWSCertificateManagerException;
import com.amazonaws.services.ec2.model.AmazonEC2Exception;
import com.amazonaws.services.ec2.model.DescribeTagsResult;
import com.amazonaws.services.ec2.model.TagDescription;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.AWSSecretsManagerException;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

public class EmrTlsFromSecretsManager extends AbstractEmrTlsProvider {

	public static final String SM_SSL_EMRCERT = "sm:ssl:emrcert";
	public static final String SM_SSL_EMRPRIVATE = "sm:ssl:emrprivate";

	private String sm_privateKey;
	private String sm_certificate;

	public EmrTlsFromSecretsManager() {
		super();
	}

	@Override
	protected void assignTags(DescribeTagsResult tags){
		if(tags != null) {
			//iterate through all tags
			for(TagDescription tag:tags.getTags()) {
				//get name of SM secret name storing CA public certificate
				if (tag.getKey().equals(SM_SSL_EMRCERT)) {
					this.sm_certificate = tag.getValue();
				}
				//get name of SM secret name storing CA certificate private key
				if (tag.getKey().equals(SM_SSL_EMRPRIVATE)) {
					this.sm_privateKey = tag.getValue();
				}
			}
		} else {
			System.out.println("No Tags");
		}
	}

	@Override
	protected void getCertificates() {
		//read CA certificates from secrets manager
		this.tlsPrivateKey = getSecret(this.sm_privateKey);
		this.tlsCertificateChain = getSecret(this.sm_certificate);
		this.tlsCertificate = this.tlsCertificateChain;
	}

	public String getSecret(String secretName) {

		String endpoint = "secretsmanager."+region+".amazonaws.com";
//		System.out.println("Secrets Manager endpoint:" + endpoint);

		AwsClientBuilder.EndpointConfiguration config = new AwsClientBuilder.EndpointConfiguration(endpoint, region);
		AWSSecretsManagerClientBuilder clientBuilder = AWSSecretsManagerClientBuilder.standard();
		clientBuilder.setEndpointConfiguration(config);
		AWSSecretsManager client = clientBuilder.build();

		String secret;

		GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest()
				.withSecretId(secretName).withVersionStage("AWSCURRENT");
		GetSecretValueResult getSecretValueResult = retry(request-> {
			GetSecretValueResult result = null;
			try {
				result = client.getSecretValue(request);
			}
			catch (AWSSecretsManagerException ex) {
				if (RetryUtils.isThrottlingException(ex)) {
					System.out.println("Got getSecretValue ThrottlingException: " + ex.getMessage());
					return null;
				} else {
					System.out.println("The request failed due to: " + ex.getMessage());
					throw ex;
				}
			}
			return result;
		}, getSecretValueRequest);


		if(getSecretValueResult.getSecretString() != null) {
			secret = getSecretValueResult.getSecretString();
		}
		else {
			ByteBuffer binarySecretData = getSecretValueResult.getSecretBinary();
			secret = new String(Base64.getDecoder().decode(binarySecretData).array());
		}

//		System.out.println(secret);
		return secret;
	}

	public static void main(String[] args) {
//		EmrTlsFromSecretsManager emrTls = new EmrTlsFromSecretsManager();
//		emrTls.getSecret("testsecret");
//		emrTls.getTlsArtifacts();

		System.out.println("Creating service");
		int totalThreads = 100;
		if(args.length>0) totalThreads=Integer.parseInt(args[0]);
		ExecutorService service = Executors.newFixedThreadPool(totalThreads);

		List<Callable<Integer>> futureList = new ArrayList<>();
		for ( int i=0; i<totalThreads; i++){
			int cnt = i;
			Callable<Integer> tlsCallable = () -> {
				EmrTlsFromSecretsManager emrTls = new EmrTlsFromSecretsManager();
				emrTls.getTlsArtifacts();
				System.out.println("cnt:"+cnt);
				return cnt;
			};
			futureList.add(tlsCallable);
		}
		System.out.println("Starting service");
		try{
			List<Future<Integer>> futures = service.invokeAll(futureList);
			for(Future<Integer> f:futures) {
				try {
					f.get();
				} catch (ExecutionException ex) {
					ex.getCause().printStackTrace();
				}
			}

			service.shutdown();
			if(!service.awaitTermination(10, TimeUnit.SECONDS)){
				System.out.println("Long waiting: calling shutdownNow()...");
				service.shutdownNow();
				System.out.println("force shutdown");
			}
			else {
				System.out.println("Completed");
			}
		}catch(Exception err){
			err.printStackTrace();
		}
	}
}
