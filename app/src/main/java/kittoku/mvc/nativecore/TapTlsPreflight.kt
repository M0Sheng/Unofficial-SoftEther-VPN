package kittoku.mvc.nativecore

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.SystemClock
import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import kittoku.mvc.network.PhysicalUnderlay
import kittoku.mvc.network.PhysicalUnderlayLostException
import kittoku.mvc.network.physicalUnderlay
import kittoku.mvc.network.physicalUnderlays
import kittoku.mvc.tls.CertificateIdentity
import kittoku.mvc.tls.CertificateEndpoint
import kittoku.mvc.tls.CertificateReviewException
import kittoku.mvc.tls.ReviewingTrustManager
import java.io.Closeable
import java.io.IOException
import java.io.InterruptedIOException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.UnknownHostException
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

/** Verifies the native client's server before its credentials are made available. */
internal class TapTlsPreflight(
    private val connectivity: ConnectivityManager,
    private val modeLabel: String = "TAP",
    private val onNetworkLost: (Network) -> Unit = {},
    private val diagnostic: (level: String, tag: String, message: String) -> Unit,
) : Closeable {
    private data class Destination(val underlay: PhysicalUnderlay, val address: InetAddress)
    data class VerifiedServer(val network: Network, val certificatePem: ByteArray)

    private val lock = Any()
    @Volatile private var retainedNetwork: Network? = null
    private val networkRequest = object : ConnectivityManager.NetworkCallback() {
        override fun onLost(network: Network) {
            if (network == retainedNetwork) onNetworkLost(network)
        }
    }
    private var retained = false
    private var closed = false
    private var activeSocket: Socket? = null

    fun verify(host: String, port: Int, sha256: String, protocol: String, cipherSuites: Set<String>?,
               underlyingNetwork: Network): VerifiedServer {
        val destination = resolveOnUnderlay(host, underlyingNetwork)
        retain(destination.underlay)

        val certificate = withVerifiedSocket(destination, host, port, sha256, protocol, cipherSuites) { _, leaf -> leaf }
        ensureOpen()
        val encoding = Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(certificate.encoded)
        val pem = "-----BEGIN CERTIFICATE-----\n$encoding\n-----END CERTIFICATE-----\n"
        return VerifiedServer(destination.underlay.network, pem.toByteArray(Charsets.US_ASCII))
    }

    /** Discovery only opens a transient socket and sends no VPN account information. */
    fun listHubs(endpoint: CertificateEndpoint, sha256: String, protocol: String, cipherSuites: Set<String>?): List<String> {
        val host = endpoint.host
        val destination = resolveOnUnderlay(host)
        val address = destination.address.hostAddress ?: throw IOException(appText(R.string.network_runtime_error_preflight_no_server_address))
        val authority = if (':' in address) "[$address]:${endpoint.port}" else "$address:${endpoint.port}"
        return withVerifiedSocket(destination, host, endpoint.port, sha256, protocol, cipherSuites) { tls, _ ->
            SoftEtherHubDiscovery.fetch(tls.inputStream, tls.outputStream, authority)
        }
    }

    private fun <T> withVerifiedSocket(destination: Destination, host: String, port: Int, sha256: String,
                                       protocol: String, cipherSuites: Set<String>?,
                                       exchange: (SSLSocket, X509Certificate) -> T): T =
        destination.underlay.network.socketFactory.createSocket().use { socket ->
            synchronized(lock) {
                ensureOpen()
                activeSocket = socket
            }
            try {
                connect(socket, destination, port)
                withVerifiedTls(socket, host, port, sha256, protocol, cipherSuites, exchange)
            } finally {
                synchronized(lock) {
                    if (activeSocket === socket) activeSocket = null
                }
            }
        }

    private fun resolveOnUnderlay(host: String, underlyingNetwork: Network? = null): Destination {
        ensureOpen()
        val underlays = if (underlyingNetwork == null) connectivity.physicalUnderlays()
            else listOfNotNull(connectivity.physicalUnderlay(underlyingNetwork))
        if (underlays.isEmpty()) throw PhysicalUnderlayLostException(
            underlyingNetwork, R.string.network_runtime_error_preflight_no_underlay,
        )

        var lastDnsFailure: UnknownHostException? = null
        var lostDuringDns: PhysicalUnderlayLostException? = null
        for (underlay in underlays) {
            ensureOpen()
            val started = SystemClock.elapsedRealtime()
            try {
                val addresses = underlay.network.getAllByName(host)
                val address = addresses.firstOrNull { it is Inet4Address } ?: addresses.firstOrNull()
                    ?: throw UnknownHostException(appText(R.string.network_runtime_error_preflight_no_dns_answer))
                diagnostic("INFO", "DNS", "$modeLabel preflight resolved $host to ${address.hostAddress} " +
                    "via network=${underlay.network} elapsed_ms=${SystemClock.elapsedRealtime() - started}")
                return Destination(underlay, address)
            } catch (failure: UnknownHostException) {
                diagnostic("WARN", "DNS", "$modeLabel preflight resolution failed via network=${underlay.network} " +
                    "elapsed_ms=${SystemClock.elapsedRealtime() - started}: ${failure.message}")
                if (connectivity.physicalUnderlay(underlay.network) == null) {
                    lostDuringDns = PhysicalUnderlayLostException(underlay.network, cause = failure)
                } else {
                    lastDnsFailure?.let(failure::addSuppressed)
                    lastDnsFailure = failure
                }
            }
        }
        throw lostDuringDns ?: lastDnsFailure ?: UnknownHostException(appText(R.string.network_runtime_error_preflight_underlay_dns))
    }

    private fun retain(underlay: PhysicalUnderlay) {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .addTransportType(underlay.transport)
            .build()
        synchronized(lock) {
            ensureOpen()
            check(!retained)
            retainedNetwork = underlay.network
            connectivity.requestNetwork(request, networkRequest)
            retained = true
        }
        val current = connectivity.physicalUnderlay(underlay.network)
        if (current?.transport != underlay.transport) throw PhysicalUnderlayLostException(
            underlay.network, R.string.network_runtime_error_preflight_underlay_lost,
        )
        diagnostic("INFO", "NETWORK", "$modeLabel preflight selected network=${underlay.network} " +
            "interface=${connectivity.getLinkProperties(underlay.network)?.interfaceName}")
    }

    private fun connect(socket: Socket, destination: Destination, port: Int) {
        val started = SystemClock.elapsedRealtime()
        val endpoint = InetSocketAddress(destination.address, port)
        try {
            socket.connect(endpoint, CONNECT_TIMEOUT_MS)
            diagnostic("INFO", "TCP", "$modeLabel preflight connected to $endpoint " +
                "elapsed_ms=${SystemClock.elapsedRealtime() - started}")
        } catch (failure: Exception) {
            diagnostic("ERROR", "TCP", "$modeLabel preflight connect failed endpoint=$endpoint " +
                "elapsed_ms=${SystemClock.elapsedRealtime() - started}: ${failure.message}")
            throw failure
        }
    }

    private fun <T> withVerifiedTls(socket: Socket, host: String, port: Int, sha256: String, protocol: String,
                                    cipherSuites: Set<String>?, exchange: (SSLSocket, X509Certificate) -> T): T {
        val started = SystemClock.elapsedRealtime()
        try {
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf(ReviewingTrustManager(sha256)), null)
            return (sslContext.socketFactory.createSocket(socket, host, port, true) as SSLSocket).use { tls ->
                tls.soTimeout = HANDSHAKE_TIMEOUT_MS
                tls.sslParameters = tls.sslParameters.apply {
                    if (sha256.isEmpty()) endpointIdentificationAlgorithm = "HTTPS"
                    if (protocol != "DEFAULT") protocols = arrayOf(protocol)
                    if (cipherSuites != null) {
                        this.cipherSuites = tls.supportedCipherSuites.filter(cipherSuites::contains).toTypedArray()
                    }
                }
                val trust = if (sha256.isEmpty()) "system_CA_and_hostname" else "remembered_leaf_certificate"
                diagnostic("INFO", "TLS", "$modeLabel preflight handshake started trust=$trust " +
                    "protocols=${tls.enabledProtocols.joinToString()} timeout_ms=$HANDSHAKE_TIMEOUT_MS")
                tls.startHandshake()
                val session = tls.session
                val certificate = session.peerCertificates.firstOrNull() as? X509Certificate
                    ?: throw IOException(appText(R.string.network_runtime_error_preflight_no_certificate))
                diagnostic("INFO", "TLS", "$modeLabel preflight handshake complete protocol=${session.protocol} " +
                    "cipher=${session.cipherSuite} elapsed_ms=${SystemClock.elapsedRealtime() - started}")
                logIdentity("INFO", CertificateIdentity.from(certificate))
                exchange(tls, certificate)
            }
        } catch (failure: Exception) {
            diagnostic("ERROR", "TLS", "$modeLabel preflight failed " +
                "elapsed_ms=${SystemClock.elapsedRealtime() - started}: ${failure.javaClass.simpleName}: ${failure.message}")
            generateSequence<Throwable>(failure) { it.cause }.take(16)
                .filterIsInstance<CertificateReviewException>().firstOrNull()?.let { logIdentity("WARN", it.identity) }
            throw failure
        }
    }

    private fun logIdentity(level: String, identity: CertificateIdentity) {
        diagnostic(level, "TLS_CERT", "$modeLabel server certificate subject=${identity.subject} issuer=${identity.issuer} " +
            "valid_from_ms=${identity.notBeforeMillis} valid_until_ms=${identity.notAfterMillis} " +
            "names=${identity.alternativeNames} sha256=${identity.sha256}")
    }

    private fun ensureOpen() = synchronized(lock) {
        if (closed) throw InterruptedIOException(appText(R.string.network_runtime_error_preflight_verification_canceled))
    }

    override fun close() {
        val (socket, releaseNetwork) = synchronized(lock) {
            if (closed) return
            closed = true
            (activeSocket to retained).also {
                activeSocket = null
                retained = false
                retainedNetwork = null
            }
        }
        try {
            socket?.close()
        } finally {
            if (releaseNetwork) connectivity.unregisterNetworkCallback(networkRequest)
        }
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 10_000
        const val HANDSHAKE_TIMEOUT_MS = 15_000
    }
}
