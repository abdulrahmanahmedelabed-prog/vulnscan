package com.acme.api;

import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.ws.rs.*;
import java.io.File;
import java.nio.file.Files;

@Path("/users")
@RolesAllowed("user")
public class UserResource {

    @GET
    @Path("/{id}/avatar")
    public byte[] avatar(@PathParam("id") String id, @QueryParam("size") String size) throws Exception {
        return Files.readAllBytes(new File("/data/avatars/" + id + "_" + size).toPath());
    }

    @POST
    @PermitAll
    public String register(UserDto dto, @HeaderParam("X-Forwarded-For") String ip) {
        return "created";
    }

    @DELETE
    @Path("/{id}")
    @RolesAllowed("admin")
    public void delete(@PathParam("id") long id) {
    }
}
