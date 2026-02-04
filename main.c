#include <gtk/gtk.h>
#include <string.h>
#include <stdlib.h>
#include "api.h" // SPHINCS+ API
#include <stdio.h>
#include <unistd.h> 




// Globalna varijabla za poruku
char message[1024] = "";

// Funkcije za SPHINCS+
void generate_keys(GtkWidget *widget, gpointer status_label);
void save_message(GtkWidget *widget, gpointer data);
void generate_hash(GtkWidget *widget, gpointer data);
void sign_message(GtkWidget *widget, gpointer data);
void verify_signature(GtkWidget *widget, gpointer data);
void sha256(unsigned char *out, const unsigned char *in, unsigned long long inlen);
void delete_txt_files(); 

typedef struct {
    GtkWidget *message_entry;
    GtkWidget *status_label;
} Widgets;

int main(int argc, char *argv[]) {
    GtkWidget *window;
    GtkWidget *grid;
    GtkWidget *message_entry;
    GtkWidget *status_label;
    GtkWidget *save_button;               
    GtkWidget *generate_keys_button;     
    GtkWidget *generate_hash_button;      
    GtkWidget *sign_button;               
    GtkWidget *verify_button;
    Widgets widgets;



    gtk_init(&argc, &argv);

    // Glavni prozor
    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window), "Digitalni potpis");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect(window, "destroy", G_CALLBACK(delete_txt_files), NULL); 


    // Grid layout
    grid = gtk_grid_new();
    gtk_container_add(GTK_CONTAINER(window), grid);

    // Tekstni okvir za unos poruke
    message_entry = gtk_entry_new();
    gtk_grid_attach(GTK_GRID(grid), message_entry, 0, 0, 2, 1);

    // Status labela
    status_label = gtk_label_new("Status: Spreman");
    gtk_grid_attach(GTK_GRID(grid), status_label, 0, 4, 2, 1);
    //gtk_label_set_line_wrap(GTK_LABEL(status_label), TRUE);

    // Popuni strukturu widgetima
    widgets.message_entry = message_entry;
    widgets.status_label = status_label;

    // Gumb za spremanje poruke
    save_button = gtk_button_new_with_label("Spremi poruku");
    g_signal_connect(save_button, "clicked", G_CALLBACK(save_message), message_entry);
    gtk_grid_attach(GTK_GRID(grid), save_button, 0, 1, 2, 1);

    // Ostali gumbi
    generate_keys_button = gtk_button_new_with_label("Generiraj ključeve");
    g_signal_connect(generate_keys_button, "clicked", G_CALLBACK(generate_keys), status_label);
    gtk_grid_attach(GTK_GRID(grid), generate_keys_button, 0, 2, 1, 1);

    generate_hash_button = gtk_button_new_with_label("Generiraj hash");
    g_signal_connect(generate_hash_button, "clicked", G_CALLBACK(generate_hash), message_entry);
    gtk_grid_attach(GTK_GRID(grid), generate_hash_button, 1, 2, 1, 1);

    sign_button = gtk_button_new_with_label("Potpiši poruku");
    g_signal_connect(sign_button, "clicked", G_CALLBACK(sign_message), &widgets);
    gtk_grid_attach(GTK_GRID(grid), sign_button, 0, 3, 1, 1);

    verify_button = gtk_button_new_with_label("Provjeri potpis");
    g_signal_connect(verify_button, "clicked", G_CALLBACK(verify_signature), &widgets);
    gtk_grid_attach(GTK_GRID(grid), verify_button, 1, 3, 1, 1);




    gtk_widget_show_all(window);
    gtk_main();

    printf("CRYPTO_PUBLICKEYBYTES: %d\n", CRYPTO_PUBLICKEYBYTES);
printf("CRYPTO_SECRETKEYBYTES: %d\n", CRYPTO_SECRETKEYBYTES);
printf("CRYPTO_BYTES: %d\n", CRYPTO_BYTES);



    return 0;
}


// Implementacija funkcija

void generate_keys(GtkWidget *widget, gpointer status_label) {
    (void)widget;
    unsigned char public_key[CRYPTO_PUBLICKEYBYTES];
    unsigned char private_key[CRYPTO_SECRETKEYBYTES];

    if (crypto_sign_keypair(public_key, private_key) == 0) {

    printf("\n");
    printf("Javni ključ: ");
    for (size_t i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", public_key[i]);
    printf("\n");

    printf("Privatni ključ: ");
    for (size_t i = 0; i < CRYPTO_SECRETKEYBYTES; i++) printf("%02x", private_key[i]);
    printf("\n");

        FILE *pk = fopen("javni_kljuc.txt", "wb");
        fwrite(public_key, 1, CRYPTO_PUBLICKEYBYTES, pk);
        fclose(pk);

        FILE *sk = fopen("privatni_kljuc.txt", "wb");
        if (!sk) {
            fprintf(stderr, "Greška pri otvaranju datoteke za privatni ključ.\n");
            return;
        }
        fwrite(private_key, 1, CRYPTO_SECRETKEYBYTES, sk);
        fclose(sk);

        gtk_label_set_text(GTK_LABEL(status_label), "Ključevi generirani i spremljeni.");
    } else {
        gtk_label_set_text(GTK_LABEL(status_label), "Greška pri generiranju ključeva.");
    }

}

void generate_hash(GtkWidget *widget, gpointer data) {
    GtkWidget *message_entry = (GtkWidget *)data; // Cast na tekstni okvir
    const char *msg = gtk_entry_get_text(GTK_ENTRY(message_entry));
    unsigned char hash[32];

    memset(hash, 0, sizeof(hash));
    sha256(hash, (unsigned char *)msg, strlen(msg));

    FILE *hash_file = fopen("hash.txt", "wb");
    if (!hash_file) {
        printf("Greška pri otvaranju datoteke hash.txt.\n");
        return;
    }

    fwrite(hash, 1, sizeof(hash), hash_file);
    fclose(hash_file);

    printf("\n");
    printf("Hash generiran i spremljen u hash.txt.\n");
}



void sign_message(GtkWidget *widget, gpointer data) {
    Widgets *widgets = (Widgets *)data;
    GtkWidget *message_entry = widgets->message_entry;
    GtkWidget *status_label = widgets->status_label;

    const char *msg = gtk_entry_get_text(GTK_ENTRY(message_entry));
    unsigned char private_key[CRYPTO_SECRETKEYBYTES];
    unsigned char signature[CRYPTO_BYTES];
    unsigned long long signature_len;

    // Učitavanje privatnog ključa
    FILE *sk_file = fopen("privatni_kljuc.txt", "rb");
    if (!sk_file) {
        gtk_label_set_text(GTK_LABEL(status_label), "Greška: Privatni ključ nije pronađen.");
        return;
    }
    fread(private_key, 1, CRYPTO_SECRETKEYBYTES, sk_file);
    fclose(sk_file);

    printf("\n");
    printf("Privatni ključ: ");
    for (size_t i = 0; i < CRYPTO_SECRETKEYBYTES; i++) printf("%02x", private_key[i]);
    printf("\n");

    printf("Poruka za potpisivanje: %s\n", msg);

    // Generiranje potpisa
    if (crypto_sign(signature, &signature_len, (unsigned char *)msg, strlen(msg), private_key) != 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Greška pri potpisivanju poruke.");
        return;
    }

    // Spremanje potpisa
    FILE *signature_file = fopen("potpis.txt", "wb");
    if (!signature_file) {
        gtk_label_set_text(GTK_LABEL(status_label), "Greška: Ne mogu otvoriti datoteku za potpisivanje.");
        return;
    }
    fwrite(signature, 1, signature_len, signature_file);
    fclose(signature_file);

    FILE *original_message_file = fopen("original_message.txt", "w");
    if (!original_message_file) {
        gtk_label_set_text(GTK_LABEL(status_label), "Greška: Ne mogu spremiti originalnu poruku.");
        return;
    }
    fprintf(original_message_file, "%s", msg);
    fclose(original_message_file);

    gtk_label_set_text(GTK_LABEL(status_label), "Poruka potpisana i spremljena u potpis.txt.");
}





void verify_signature(GtkWidget *widget, gpointer data) {
    Widgets *widgets = (Widgets *)data;
    GtkWidget *message_entry = widgets->message_entry;
    GtkWidget *status_label = widgets->status_label;

    const char *msg = gtk_entry_get_text(GTK_ENTRY(message_entry));
    unsigned char public_key[CRYPTO_PUBLICKEYBYTES];
    unsigned char signature[CRYPTO_BYTES];
    unsigned long long mlen = strlen(msg);
    unsigned char *output_message = malloc(mlen + CRYPTO_BYTES);

    FILE *pk_file = fopen("javni_kljuc.txt", "rb");
    if (!pk_file) {
        gtk_label_set_text(GTK_LABEL(status_label), "Greška: Javni ključ nije pronađen.");
        free(output_message);
        return;
    }
    fread(public_key, 1, CRYPTO_PUBLICKEYBYTES, pk_file);
    fclose(pk_file);

    printf("\n");
    printf("Javni ključ (provjera): ");
    for (size_t i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) printf("%02x", public_key[i]);
    printf("\n");

    FILE *sig_file = fopen("potpis.txt", "rb");
    if (!sig_file) {
        gtk_label_set_text(GTK_LABEL(status_label), "Greška: Potpis nije pronađen.");
        free(output_message);
        return;
    }
    fread(signature, 1, CRYPTO_BYTES, sig_file);
    fclose(sig_file);

    if (crypto_sign_open(output_message, &mlen, signature, CRYPTO_BYTES, public_key) == 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Potpis JE valjan.");
        free(output_message);
        return;

    } 

    printf("Poruka za provjeru: %s\n", msg);

    char original_msg[1024] = {0};
    FILE *original_message_file = fopen("original_message.txt", "r");
    if (!original_message_file) {
        gtk_label_set_text(GTK_LABEL(status_label), "Greška: Originalna poruka nije pronađena.");
        free(output_message);
        return;
    }
    fgets(original_msg, sizeof(original_msg), original_message_file);
    fclose(original_message_file);


    if (strcmp(original_msg, msg) == 0) {
        gtk_label_set_text(GTK_LABEL(status_label), "Potpis JE valjan");
    } else {
        gtk_label_set_text(GTK_LABEL(status_label), "Potpis NIJE valjan");
    }


    free(output_message);

}



// Funkcija za spremanje poruke u datoteku
void save_message(GtkWidget *widget, gpointer data) {
    GtkWidget *message_entry = (GtkWidget *)data;
    const char *message = gtk_entry_get_text(GTK_ENTRY(message_entry));

    // Spremanje poruke u datoteku poruka.txt
    FILE *file = fopen("poruka.txt", "w");
    if (file == NULL) {
        printf("Greška: Ne mogu otvoriti datoteku za pisanje.\n");
        return;
    }

    fprintf(file, "%s", message);
    fclose(file);

    printf("Poruka spremljena u datoteku poruka.txt.\n");
}


void delete_txt_files() {
    // Lista datoteka za brisanje
    const char *files[] = {"poruka.txt", "hash.txt", "potpis.txt", "javni_kljuc.txt", "privatni_kljuc.txt"};
    size_t num_files = sizeof(files) / sizeof(files[0]);

    for (size_t i = 0; i < num_files; i++) {
        if (unlink(files[i]) == 0) {
            printf("Datoteka %s izbrisana.\n", files[i]);
        } else {
            printf("Greška: Datoteka %s nije pronađena ili se ne može izbrisati.\n", files[i]);
        }
    }
}