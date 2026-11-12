// expect-none: DF010
#include <curl/curl.h>
#include <fcgiapp.h>

void handle(FCGX_Request *request) {
    const char *target = FCGX_GetParam("HTTP_X_FETCH", request->envp);
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://status.example.com/health");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}
