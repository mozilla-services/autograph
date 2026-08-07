// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.cloud.kms.pkcs11.fakekms;

import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.api.gax.rpc.TransportChannelProvider;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.devtools.build.runfiles.Runfiles;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

/** FakeKms provides a Java language binding to a fake Cloud KMS server. */
public class FakeKms implements AutoCloseable {

  private static final String FAKEKMS_PATH =
      "com_google_kmstools/fakekms/main/fakekms_/fakekms"
          + (System.getProperty("os.name").startsWith("Windows") ? ".exe" : "");

  private final Process process;
  private final String serverAddress;
  private ArrayList<GrpcTransportChannel> channels;

  /** Creates and starts a new Fake KMS server. */
  public FakeKms() throws IOException {
    String serverPath = Runfiles.create().rlocation(FAKEKMS_PATH);
    process = Runtime.getRuntime().exec(serverPath);
    serverAddress = new BufferedReader(new InputStreamReader(process.getInputStream())).readLine();
    channels = new ArrayList<>();
  }

  /** Returns a new KMS client that is wired to this fake. */
  public KeyManagementServiceClient newClient() throws IOException {
    GrpcTransportChannel channel = GrpcTransportChannel.create(
        ManagedChannelBuilder.forTarget(serverAddress).usePlaintext().build());
    channels.add(channel);
    TransportChannelProvider channelProvider =
        FixedTransportChannelProvider.create(channel);

    KeyManagementServiceSettings clientSettings =
        KeyManagementServiceSettings.newBuilder()
            .setTransportChannelProvider(channelProvider)
            .setCredentialsProvider(new NoCredentialsProvider())
            .build();

    return KeyManagementServiceClient.create(clientSettings);
  }

  public String getServerAddress() {
    return serverAddress;
  }

  /** Stops the fake server and releases all resources associated with it. */
  @Override
  public void close() {
    for (GrpcTransportChannel c : channels) {
      c.close();
    }

    if (process.isAlive()) {
      process.destroy();
    }
  }
}
