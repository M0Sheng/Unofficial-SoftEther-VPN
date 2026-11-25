package kittoku.mvc.routing.root

internal object RootRoutingWire {
    fun initial(ownerUid: Int, underlayNetId: Int, iface: String, token: String,
                ranges: List<RootUidRange>, cidrs: List<String>, tapInterfaceName: String? = null): String {
        require(ownerUid >= 10000 && underlayNetId in 100..65535)
        val tapName = tapInterfaceName ?: "eth9" // Only the old seven-field V1 form uses this legacy name.
        validateTapName(tapName)
        require(iface.matches(Regex("[A-Za-z0-9_.:-]{1,15}")) && iface != tapName)
        require(token.matches(Regex("[A-Za-z0-9-]{1,64}")))
        require(ranges.size <= 1024 && cidrs.size <= 256)
        require(cidrs.all { it.matches(Regex("[0-9a-fA-F:.]+/[0-9]{1,3}")) })
        val fields = listOf("V1", ownerUid, underlayNetId, iface, token,
            ranges.joinToString(",").ifEmpty { "-" }, cidrs.joinToString(",").ifEmpty { "-" })
        return (if (tapInterfaceName == null) fields else fields + tapName).joinToString("\t")
    }

    fun validateTapName(name: String) {
        require(name.matches(Regex("(?:eth|usb)[0-9]{1,12}"))) { "Invalid owned virtual-adapter interface name" }
    }

    fun attach(netId: Int, ifIndex: Int, tapInterfaceName: String): String {
        require(netId in 100..65535 && ifIndex > 0)
        validateTapName(tapInterfaceName)
        return "ATTACH\t$netId\t$ifIndex\t$tapInterfaceName"
    }
}
