use lopdf::{Dictionary, Document, Object, Stream};

fn main() {
    let mut doc = Document::with_version("1.4");

    let font_dict = Dictionary::from_iter(vec![
        ("Type", Object::Name(b"Font".to_vec())),
        ("Subtype", Object::Name(b"Type1".to_vec())),
        ("BaseFont", Object::Name(b"Helvetica".to_vec())),
    ]);
    let font_id = doc.add_object(font_dict);

    let content = b"BT\n/F1 12 Tf\n100 700 Td\n(Hello World - Test PDF for Remote Signing) Tj\nET\n";
    let content_stream = Stream::new(Dictionary::new(), content.to_vec());
    let content_id = doc.add_object(content_stream);

    let font_res = Dictionary::from_iter(vec![
        ("F1", Object::Reference(font_id)),
    ]);
    let resources = Dictionary::from_iter(vec![
        ("Font", Object::Dictionary(font_res)),
    ]);

    let page_id = doc.add_object(Dictionary::from_iter(vec![
        ("Type", Object::Name(b"Page".to_vec())),
        (
            "MediaBox",
            Object::Array(vec![
                0.into(),
                0.into(),
                612.into(),
                792.into(),
            ]),
        ),
        ("Contents", Object::Reference(content_id)),
        ("Resources", Object::Dictionary(resources)),
    ]));

    let pages_id = doc.add_object(Dictionary::from_iter(vec![
        ("Type", Object::Name(b"Pages".to_vec())),
        ("Kids", Object::Array(vec![Object::Reference(page_id)])),
        ("Count", Object::Integer(1)),
    ]));

    // Set parent on the page
    if let Ok(page) = doc.get_object_mut(page_id) {
        if let Ok(dict) = page.as_dict_mut() {
            dict.set("Parent", Object::Reference(pages_id));
        }
    }

    let catalog_id = doc.add_object(Dictionary::from_iter(vec![
        ("Type", Object::Name(b"Catalog".to_vec())),
        ("Pages", Object::Reference(pages_id)),
    ]));

    doc.trailer.set("Root", Object::Reference(catalog_id));

    let dir = std::env::current_dir().expect("Failed to get cwd");
    let out_dir = dir.join("test-files");
    std::fs::create_dir_all(&out_dir).expect("Failed to create test-files dir");
    let path = out_dir.join("sample.pdf");
    doc.save(&path).expect("Failed to save PDF");
    println!("Created {:?}", path);
}

