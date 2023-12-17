// @generated automatically by Diesel CLI.

diesel::table! {
    user (id) {
        id -> Text,
        display_name -> Text,
        email -> Text,
        hashed_and_salted_password -> Text,
        two_fa_client_secret -> Text,
    }
}
