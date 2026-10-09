package eu.exeris.caps.mfatotp.internal.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Base32Test {

    @Test
    @DisplayName("RFC 4648 test vectors for Base32")
    void testRfcVectors() {
        assertThat(Base32.encode("".getBytes(StandardCharsets.UTF_8))).isEqualTo("");
        assertThat(Base32.encode("f".getBytes(StandardCharsets.UTF_8))).isEqualTo("MY");
        assertThat(Base32.encode("fo".getBytes(StandardCharsets.UTF_8))).isEqualTo("MZXQ");
        assertThat(Base32.encode("foo".getBytes(StandardCharsets.UTF_8))).isEqualTo("MZXW6");
        assertThat(Base32.encode("foob".getBytes(StandardCharsets.UTF_8))).isEqualTo("MZXW6YQ");
        assertThat(Base32.encode("fooba".getBytes(StandardCharsets.UTF_8))).isEqualTo("MZXW6YTB");
        assertThat(Base32.encode("foobar".getBytes(StandardCharsets.UTF_8))).isEqualTo("MZXW6YTBOI");

        assertThat(new String(Base32.decode(""), StandardCharsets.UTF_8)).isEqualTo("");
        assertThat(new String(Base32.decode("MY"), StandardCharsets.UTF_8)).isEqualTo("f");
        assertThat(new String(Base32.decode("MZXQ"), StandardCharsets.UTF_8)).isEqualTo("fo");
        assertThat(new String(Base32.decode("MZXW6"), StandardCharsets.UTF_8)).isEqualTo("foo");
        assertThat(new String(Base32.decode("MZXW6YQ"), StandardCharsets.UTF_8)).isEqualTo("foob");
        assertThat(new String(Base32.decode("MZXW6YTB"), StandardCharsets.UTF_8)).isEqualTo("fooba");
        assertThat(new String(Base32.decode("MZXW6YTBOI"), StandardCharsets.UTF_8)).isEqualTo("foobar");
    }

    @Test
    @DisplayName("Base32 case insensitivity and padding stripping")
    void testCaseAndPadding() {
        assertThat(new String(Base32.decode("mzxw6ytboi======"), StandardCharsets.UTF_8)).isEqualTo("foobar");
        assertThat(new String(Base32.decode("MZXW6YTBOI==="), StandardCharsets.UTF_8)).isEqualTo("foobar");
    }

    @Test
    @DisplayName("Invalid characters throw IllegalArgumentException")
    void testInvalidCharacters() {
        assertThatThrownBy(() -> Base32.decode("MZXW68")) // 8 is invalid Base32
                .isInstanceOf(IllegalArgumentException.class);
    }
}
