//! Generate a test signature image (PNG) for visible signature testing.

fn main() {
    let width: u32 = 200;
    let height: u32 = 100;

    // Create RGBA pixel buffer: blue border with white fill
    let mut pixels: Vec<u8> = Vec::with_capacity((width * height * 4) as usize);
    for y in 0..height {
        for x in 0..width {
            if x < 3 || x >= width - 3 || y < 3 || y >= height - 3 {
                // Blue border
                pixels.extend_from_slice(&[0, 51, 153, 255]);
            } else if y >= height / 2 {
                // Light blue bottom half
                pixels.extend_from_slice(&[220, 230, 255, 240]);
            } else {
                // White top half with slight transparency
                pixels.extend_from_slice(&[255, 255, 255, 230]);
            }
        }
    }

    // Encode as PNG
    let path = std::path::Path::new("test-files/signature-image.png");
    let file = std::fs::File::create(path).expect("Failed to create PNG file");
    let writer = std::io::BufWriter::new(file);

    let mut encoder = image::codecs::png::PngEncoder::new(writer);
    use image::ImageEncoder;
    encoder
        .write_image(&pixels, width, height, image::ExtendedColorType::Rgba8)
        .expect("Failed to encode PNG");

    println!("Created {} ({}x{} RGBA)", path.display(), width, height);
}

