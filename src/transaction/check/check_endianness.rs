// Function to check the system's native endianness
pub fn is_system_little_endian() -> bool {
    cfg!(target_endian = "little")
}

// Function to infer endianness of a byte slice representing a u32
// Returns true for little-endian, false for big-endian, or None if ambiguous
pub fn infer_endianness(bytes: &[u8], expected_value: u32) -> Option<bool> {
    if bytes.len() != 4 {
        return None; // Need exactly 4 bytes for a u32
    }

    // Interpret bytes as little-endian
    let little_endian = u32::from_le_bytes(bytes.try_into().unwrap());
    // Interpret bytes as big-endian
    let big_endian = u32::from_be_bytes(bytes.try_into().unwrap());

    // Compare with expected value
    if little_endian == expected_value && big_endian != expected_value {
        Some(true) // Little-endian
    } else if big_endian == expected_value && little_endian != expected_value {
        Some(false) // Big-endian
    } else {
        None // Ambiguous (e.g., bytes could be interpreted either way, or don't match expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_endianness() {
        let is_little = is_system_little_endian();
        println!("System is {}", if is_little { "little-endian" } else { "big-endian" });
        // No assertion here since endianness depends on the system
    }

    #[test]
    fn test_infer_endianness() {
        let value: u32 = 0x12345678;

        // Little-endian: least significant byte first
        let little_endian_bytes = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(
            infer_endianness(&little_endian_bytes, value),
            Some(true),
            "Should detect little-endian"
        );

        // Big-endian: most significant byte first
        let big_endian_bytes = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(
            infer_endianness(&big_endian_bytes, value),
            Some(false),
            "Should detect big-endian"
        );

        // Ambiguous case (e.g., all bytes are the same)
        let ambiguous_bytes = [0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            infer_endianness(&ambiguous_bytes, 0),
            None,
            "Should be ambiguous"
        );

        // Wrong length
        let wrong_length = [0x12, 0x34];
        assert_eq!(
            infer_endianness(&wrong_length, value),
            None,
            "Should fail due to incorrect length"
        );
    }
}