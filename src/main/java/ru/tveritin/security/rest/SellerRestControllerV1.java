package ru.tveritin.security.rest;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import ru.tveritin.security.model.Seller;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/api/v1/sellers")
public class SellerRestControllerV1 {
    private List<Seller> Sellers = Stream.of(new Seller(1L,"Ivan","Ivanov"),
            new Seller(2L,"Sergey", "Sergeev"),
            new Seller(3L,"Petr","Petrov")).collect(Collectors.toList());

    @GetMapping
    public List<Seller> getAll() {
        return Sellers;
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('sellers:read')")
    public Seller getById(@PathVariable Long id){
        return Sellers.stream().filter(seller -> seller.getId().equals(id)).findFirst().orElse(null);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('sellers:write')")
    public Seller create(@RequestBody Seller seller){
        this.Sellers.add(seller);
        return seller;
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('sellers:write')") //логика доступа к методам на основе прав пользователя через аннотацию
    public void deleteById(@PathVariable Long id){
        this.Sellers.removeIf(seller -> seller.getId().equals(id));
    }
}
