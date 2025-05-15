pub const REQ_GET_CLIENT_UUID: &str = "SELECT uuid FROM client;";
pub const REQ_GET_CLIENT: &str = "SELECT
    c.id AS client_id,
    ec.key_type AS identity_key_type,
    ec.public_key AS identity_key_public_key,
    ec.private_key AS identity_key_private_key,
    iek.uuid AS curve_prekey_uuid,
    ec2.key_type AS curve_prekey_key_type,
    ec2.public_key AS curve_prekey_public_key,
    ec2.private_key AS curve_prekey_private_key,
    ipk.uuid AS last_resort_prekey_uuid,
    pk.key_type AS last_resort_prekey_key_type,
    pk.public_key AS last_resort_prekey_public_key,
    pk.private_key AS last_resort_prekey_private_key
FROM
    client c
JOIN
    elliptic_curve_keypair ec ON c.identity_key_id = ec.id
JOIN
    identified_elliptic_curve_keypair iek ON c.curve_prekey_id = iek.id
JOIN
    elliptic_curve_keypair ec2 ON iek.elliptic_curve_keypair_id = ec2.id
JOIN
    identified_pqkem_keypair ipk ON c.last_resort_prekey_id = ipk.id
JOIN
    pqkem_keypair pk ON ipk.pqkem_keypair_id = pk.id;";

pub const REQ_INSERT_CLIENT: &str = "INSERT INTO client (uuid, identity_key_id, curve_prekey_id, last_resort_prekey_id) VALUES (?1, ?2, ?3, ?4) RETURNING id";
pub const REQ_UPDATE_CLIENT_CURVE_PREKEY: &str =
    "UPDATE client SET curve_prekey_id = ?2 WHERE id = ?1";
pub const REQ_UPDATE_CLIENT_LAST_RESORT_PQKEM_PREKEY: &str =
    "UPDATE client SET last_resort_prekey_id = ?2 WHERE id = ?1";

pub const REQ_INSERT_ELLIPTIC_CURVE_KEYPAIR: &str = "INSERT INTO elliptic_curve_keypair (key_type, public_key, private_key) VALUES (?1, ?2, ?3) RETURNING id";

pub const REQ_INSERT_PQKEM_KEYPAIR: &str = "INSERT INTO pqkem_keypair (key_type, public_key, private_key) VALUES (?1, ?2, ?3) RETURNING id";

pub const REQ_INSERT_IDENTIFIED_ELLIPTIC_CURVE_KEYPAIR: &str = "INSERT INTO identified_elliptic_curve_keypair (uuid, elliptic_curve_keypair_id) VALUES (?1, ?2) RETURNING id";

pub const REQ_INSERT_IDENTIFIED_PQKEM_KEYPAIR: &str =
    "INSERT INTO identified_pqkem_keypair (uuid, pqkem_keypair_id) VALUES (?1, ?2) RETURNING id";

pub const REQ_GET_CLIENT_ONE_TIME_CURVE_PREKEY: &str = "SELECT
    iec.uuid AS uuid,
    ec.key_type AS key_type,
    ec.public_key AS public_key,
    ec.private_key AS private_key
FROM
    one_time_curve_prekey otcp
JOIN
    identified_elliptic_curve_keypair iec ON otcp.identified_elliptic_curve_keypair_id = iec.id
JOIN
    elliptic_curve_keypair ec ON iec.elliptic_curve_keypair_id = ec.id
WHERE
    otcp.client_id = ?1
";
pub const REQ_INSERT_ONE_TIME_CURVE_PREKEY: &str = "INSERT INTO one_time_curve_prekey (client_id, identified_elliptic_curve_keypair_id) VALUES (?1, ?2) RETURNING id";

pub const REQ_GET_CLIENT_ONE_TIME_PQKEM_PREKEY: &str = "SELECT
    ip.uuid AS uuid,
    pk.key_type AS key_type,
    pk.public_key AS public_key,
    pk.private_key AS private_key
FROM
    one_time_pqkem_prekey otpp
JOIN
    identified_pqkem_keypair ip ON otpp.identified_pqkem_keypair_id = ip.id
JOIN
    pqkem_keypair pk ON ip.pqkem_keypair_id = pk.id
WHERE
    otpp.client_id = ?1
";
pub const REQ_INSERT_ONE_TIME_PQKEM_PREKEY: &str = "INSERT INTO one_time_pqkem_prekey (client_id, identified_pqkem_keypair_id) VALUES (?1, ?2) RETURNING id";
