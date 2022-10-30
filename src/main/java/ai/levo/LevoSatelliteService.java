package ai.levo;

import okhttp3.ResponseBody;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.POST;

public interface LevoSatelliteService {
    @POST("/1.0/ebpf/traces")
    Call<ResponseBody> sendHttpMessage(@Body HttpMessage message);
}
