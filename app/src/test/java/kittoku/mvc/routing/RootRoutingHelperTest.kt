package kittoku.mvc.routing

import java.lang.reflect.Modifier

internal object RootRoutingHelperTest {
    @JvmStatic
    fun main(args: Array<String>) {
        var passed = 0
        fun accepts(block: () -> Unit) {
            block()
            passed++
        }
        fun rejects(block: () -> Unit) {
            try {
                block()
            } catch (_: Exception) {
                passed++
                return
            }
            error("Expected rejection")
        }

        accepts {
            val method = RootRoutingHelper::class.java.getMethod("main", Array<String>::class.java)
            check(Modifier.isStatic(method.modifiers) && method.returnType == Void.TYPE)
        }

        val valid = "V1\t10425\t294\trmnet_data4\ttest-session\t10000-10002,20000-20002\t192.168.1.0/24,2001:db8::/32"
        accepts { check(RootRoutingHelper.Config(valid).wire() == valid) }
        for ((original, replacement) in listOf(
            "10000-10002" to "0-10002",
            "10000-10002" to "110000-110002",
            "10000-10002" to "10003-10002",
            "20000-20002" to "10001-10004",
            "rmnet_data4" to "eth9",
            "rmnet_data4" to "foo;id",
            "192.168.1.0/24" to "example.com/24",
            "192.168.1.0/24" to "999.1.1.1/24",
            "2001:db8::/32" to "2001:db8::/129",
        )) {
            rejects { RootRoutingHelper.Config(valid.replace(original, replacement)) }
        }
        rejects { RootRoutingHelper.numericCidr("127.1/32") }
        accepts { RootRoutingHelper.numericCidr("2001:db8::1/128") }

        val payload = "NETD\t$valid"
        val record = RootRoutingHelper.checkedRecord(payload)
        accepts { check(RootRoutingHelper.readRecord(record) == payload) }
        rejects { RootRoutingHelper.readRecord("f$record") }
        rejects { RootRoutingHelper.readRecord("123 invalid-base64") }

        accepts { RootRoutingHelper.validateAction(RootRoutingHelper.Action("NETD", valid)) }
        accepts { RootRoutingHelper.validateAction(RootRoutingHelper.Action("RULE", "-4\t14500\t298\t1030\tuidrange\t10425-10425")) }
        accepts { RootRoutingHelper.validateAction(RootRoutingHelper.Action("RULE", "-6\t14510\t298\t1030\tto\t2001:db8::/32")) }
        rejects { RootRoutingHelper.validateAction(RootRoutingHelper.Action("RULE", "-4\t14500\t298\t1030\tuidrange\t1000-1000")) }
        rejects { RootRoutingHelper.validateAction(RootRoutingHelper.Action("RULE", "-4\t14510\t298\t1030\tto\t2001:db8::/32")) }
        rejects { RootRoutingHelper.validateAction(RootRoutingHelper.Action("RULE", "-4\t10000\t298\t1030\tto\t0.0.0.0/0")) }
        rejects { RootRoutingHelper.validateAction(RootRoutingHelper.Action("EXEC", "id")) }

        val world = listOf("-4", "14510", "298", "1030", "to", "0.0.0.0/0")
        val host = listOf("-4", "14510", "298", "1030", "to", "1.2.3.4/32")
        val host6 = listOf("-6", "14510", "298", "1030", "to", "2001:db8::1/128")
        val tables = setOf("1030", "rmnet_data4")
        accepts { check(RootRoutingHelper.ruleLineMatches("14510: from all fwmark 0x12a/0xffff iif lo lookup rmnet_data4", world, tables)) }
        accepts { check(RootRoutingHelper.ruleLineMatches("14510: from all to 1.2.3.4 fwmark 0x12a/0xffff iif lo lookup 1030", host, tables)) }
        accepts { check(!RootRoutingHelper.ruleLineMatches("14510: from all to 1.2.3.4 fwmark 0x12a/0xffff iif lo lookup 1031", host, tables)) }
        accepts { check(RootRoutingHelper.ruleLineMatches("14510: from all to 2001:db8::1 fwmark 0x12a/0xffff iif lo lookup 1030", host6, tables)) }

        val init = "init-12345678-1234-1234-1234-123456789abc.cfg"
        accepts { RootRoutingHelper.validateInitName(init) }
        rejects { RootRoutingHelper.validateInitName("../$init") }
        rejects { RootRoutingHelper.validateInitName("journal.v1") }
        rejects { RootRoutingHelper.validateInitName("$init/other") }

        val named = "$valid\tusb3"
        val dynamic = RootRoutingHelper.Config(named)
        val legacy = RootRoutingHelper.Config(valid)
        accepts { check(dynamic.wire() == named && dynamic.tapName == "usb3") }
        accepts { check(legacy.tapName == "eth9") }
        accepts { RootRoutingHelper.Config(valid.replace("rmnet_data4", "eth9") + "\teth10") }
        rejects { RootRoutingHelper.Config(valid.replace("rmnet_data4", "usb3") + "\tusb3") }
        for (bad in listOf("eth", "usb", "wlan0", "tap0", "eth1;id", "usb1\nSTOP", "eth1234567890123", "eth\uFF11", "../eth1")) {
            rejects { RootRoutingHelper.Config("$valid\t$bad") }
        }
        accepts { RootRoutingHelper.validateTapName("eth123456789012") }
        accepts { RootRoutingHelper.validateTapName("usb0") }

        val attach = RootRoutingHelper.Attach("ATTACH\t298\t67\tusb3", dynamic)
        accepts { RootRoutingHelper.verifyTapGeneration(attach, "usb3", 67, 0, 0) }
        accepts { RootRoutingHelper.verifyTapGeneration(attach, "usb3", 67, 298, 67) }
        accepts { RootRoutingHelper.Attach("ATTACH\t298\t67", legacy) }
        accepts { RootRoutingHelper.Attach("ATTACH\t298\t67\teth9", legacy) }
        for (bad in listOf("298\t67", "298\t67\teth9", "294\t67\tusb3", "298\t0\tusb3", "298\t67\tusb3\textra")) {
            rejects { RootRoutingHelper.Attach("ATTACH\t$bad", dynamic) }
        }
        rejects { RootRoutingHelper.verifyTapGeneration(attach, null, -1, 0, 0) }
        rejects { RootRoutingHelper.verifyTapGeneration(attach, "eth3", 67, 0, 0) }
        rejects { RootRoutingHelper.verifyTapGeneration(attach, "usb3", 68, 0, 0) }
        rejects { RootRoutingHelper.verifyTapGeneration(attach, "usb3", 67, 299, 67) }
        rejects { RootRoutingHelper.verifyTapGeneration(attach, "usb3", 67, 298, 66) }

        accepts { RootRoutingHelper.validateAction(RootRoutingHelper.Action("NETD", named)) }
        val namedRecord = RootRoutingHelper.checkedRecord("NETD\t$named")
        accepts { check(RootRoutingHelper.readRecord(namedRecord) == "NETD\t$named") }
        println("$passed helper validation/recovery-record scenarios passed")
    }
}
